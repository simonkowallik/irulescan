#![allow(deprecated)]
use std::ffi::CString;
use std::mem::zeroed;

use num::traits::FromPrimitive;

use self::TokenType::*;
use crate::tcl;

static mut I: Option<*mut tcl::Tcl_Interp> = None;
#[allow(static_mut_refs)]
unsafe fn tcl_interp() -> *mut tcl::Tcl_Interp { unsafe {
    if I.is_none() {
        I = Some(tcl::Tcl_CreateInterp());
    }
    return I.unwrap();
}}

enum_from_primitive! {
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TokenType {
    Word = 1, // TCL_TOKEN_WORD
    SimpleWord = 2, // TCL_TOKEN_SIMPLE_WORD
    Text = 4, // TCL_TOKEN_TEXT
    Bs = 8, // TCL_TOKEN_BS
    Command = 16, // TCL_TOKEN_COMMAND
    Variable = 32, // TCL_TOKEN_VARIABLE
    SubExpr = 64, // TCL_TOKEN_SUB_EXPR
    Operator = 128, // TCL_TOKEN_OPERATOR
    ExpandWord = 256, // TCL_TOKEN_EXPAND_WORD
}
}

#[derive(Debug, PartialEq)]
pub struct TclParse<'a> {
    pub comment: Option<&'a str>,
    pub command: Option<&'a str>,
    pub tokens: Vec<TclToken<'a>>,
    pub line_number: usize, // 1-based line number
}
#[derive(Debug, PartialEq)]
pub struct TclToken<'a> {
    pub ttype: TokenType,
    pub val: &'a str,
    pub tokens: Vec<TclToken<'a>>,
}
impl<'b> TclToken<'b> {
    pub fn iter<'a>(&'a self) -> TclTokenIter<'a, 'b> {
        TclTokenIter {
            token: self,
            cur: 0,
        }
    }
    fn traverse(&self, num: usize) -> (usize, Option<&TclToken<'b>>) {
        if num == 0 {
            return (0, Some(self));
        }
        let mut numleft = num - 1;
        for subtok in self.tokens.iter() {
            match subtok.traverse(numleft) {
                (0, Some(tok)) => {
                    return (0, Some(tok));
                }
                (n, None) => {
                    numleft = n;
                }
                _ => assert!(false),
            }
        }
        return (numleft, None);
    }
}
pub struct TclTokenIter<'a, 'b: 'a> {
    token: &'a TclToken<'b>,
    cur: usize,
}
impl<'b, 'c: 'b> Iterator for TclTokenIter<'b, 'c> {
    type Item = &'b TclToken<'c>;
    fn next(&mut self) -> Option<&'b TclToken<'c>> {
        self.cur += 1;
        let ret: Option<&'b TclToken<'c>> = match self.token.traverse(self.cur - 1) {
            (0, Some(tok)) => Some(tok),
            (0, None) => None,
            x => panic!(
                "ERROR: Invalid traverse return {:?}, iterator called after finish?",
                x
            ),
        };
        return ret;
    }
}

pub fn parse_command<'a>(string: &'a str) -> (TclParse<'a>, &'a str) {
    return parse(string, true, false);
}

pub fn parse_script<'a>(script_content: &'a str) -> Vec<TclParse<'a>> {
    let mut commands = vec![];
    let mut current_script_ptr = script_content;
    // absolute_base_line_number is the 0-indexed line number in the original script_content
    // where the current_script_ptr begins.
    let mut absolute_base_line_number = 0;

    while !current_script_ptr.is_empty() {
        // Skip leading whitespace from current_script_ptr and update absolute_base_line_number
        let original_len = current_script_ptr.len();
        let trimmed_script_ptr = current_script_ptr.trim_start();
        let leading_whitespace_len = original_len - trimmed_script_ptr.len();

        if leading_whitespace_len > 0 {
            absolute_base_line_number += current_script_ptr[..leading_whitespace_len].matches('\n').count();
        }
        current_script_ptr = trimmed_script_ptr;

        if current_script_ptr.is_empty() {
            break;
        }

        // Now, current_script_ptr starts with a non-whitespace character (or is empty)
        // The line number reported by parse_command will be relative to this current_script_ptr
        let (mut parse_result, remaining_segment_after_command) = parse_command(current_script_ptr);

        // Adjust line_number to be absolute (1-based) with respect to original script_content
        // parse_result.line_number is 1-based relative to current_script_ptr
        parse_result.line_number = absolute_base_line_number + parse_result.line_number;
        
        let consumed_len_by_parse_command = current_script_ptr.len() - remaining_segment_after_command.len();

        // Add to commands list
        if parse_result.command.is_some() { // Indicates a successful parse or a structured error from `parse`
            let is_error_placeholder = parse_result.command == Some("") && parse_result.tokens.is_empty();
            // A command is meaningful if it has a non-empty command string or tokens.
            // Also add error placeholders if they consumed part of the script, or if the script part was not empty.
            let is_meaningful_command = parse_result.command.map_or(false, |c| !c.is_empty()) || !parse_result.tokens.is_empty();

            if is_meaningful_command {
                commands.push(parse_result);
            } else if is_error_placeholder {
                // If it's an error placeholder, only add it if it represents a segment of the script
                // that couldn't be parsed but wasn't just whitespace.
                // consumed_len_by_parse_command would be 0 if parse_command errored on an empty string or
                // returned "" for remaining.
                // If current_script_ptr (which was passed to parse_command) was not empty and
                // consumed_len_by_parse_command is 0, it means parse_command failed at the very start.
                if consumed_len_by_parse_command > 0 || !current_script_ptr.is_empty() {
                     commands.push(parse_result);
                }
            }
        }


        if consumed_len_by_parse_command == 0 {
            // If parse_command consumed nothing (e.g., error on empty string, or Tcl_ParseCommand itself advanced 0)
            // and current_script_ptr is not empty, we need to advance to avoid an infinite loop.
            if !current_script_ptr.is_empty() {
                // Advance past the first line to try to find the next command.
                if let Some(next_newline_pos) = current_script_ptr.find('\n') {
                    absolute_base_line_number += 1; // Consumed one line
                    current_script_ptr = &current_script_ptr[next_newline_pos + 1..];
                } else {
                    // No more newlines, so the rest of the script is effectively one line.
                    // Since nothing was consumed, we break to avoid looping on the same content.
                    break;
                }
                // Continue the loop to parse the advanced script pointer
                if !current_script_ptr.is_empty() { continue; } else { break; }
            } else {
                 // current_script_ptr is empty, and consumed_len is 0, so we are done.
                break;
            }
        }

        // Update absolute_base_line_number based on newlines in the consumed part of current_script_ptr
        let consumed_text_segment = &current_script_ptr[..consumed_len_by_parse_command];
        absolute_base_line_number += consumed_text_segment.matches('\n').count();
        
        current_script_ptr = remaining_segment_after_command;
    }
    return commands;
}

pub fn parse_expr<'a>(string: &'a str) -> (TclParse<'a>, &'a str) {
    return parse(string, false, true);
}

fn parse<'a>(string: &'a str, is_command: bool, is_expr: bool) -> (TclParse<'a>, &'a str) {
    unsafe {
        let mut parse_struct: tcl::Tcl_Parse = zeroed();
        let parse_ptr: *mut tcl::Tcl_Parse = &mut parse_struct;

        let string_cstr = CString::new(string.as_bytes()).unwrap();
        let string_ptr = string_cstr.as_ptr();
        let string_start_addr = string_ptr as usize;

        let parsed_status = match (is_command, is_expr) {
            (true, false) => tcl::Tcl_ParseCommand(tcl_interp(), string_ptr, -1, 0, parse_ptr),
            (false, true) => tcl::Tcl_ParseExpr(tcl_interp(), string_ptr, -1, parse_ptr),
            _ => panic!("UNPARSABLE: Invalid parse configuration"),
        };

        let mut calculated_line_number = 1; // 1-based, relative to the input 'string'

        if parsed_status != 0 {
            // Attempt to find line number even on parse error if commandStart is valid
            if is_command && !parse_struct.commandStart.is_null() {
                 let command_start_offset = parse_struct.commandStart as usize - string_start_addr;
                 if command_start_offset <= string.len() { // Check bounds
                    let prefix_to_command = &string[0..command_start_offset];
                    calculated_line_number = 1 + prefix_to_command.matches('\n').count();
                 }
            }
            // eprintln!("UNPARSABLE: couldn\\'t parse: \\'{}\\'", string);
            tcl::Tcl_FreeParse(parse_ptr);
            return (
                TclParse {
                    comment: Some(""), 
                    command: Some(""), // Error indicated by Some("") and empty tokens
                    tokens: vec![],
                    line_number: calculated_line_number,
                },
                "", // Tcl_Parse* documentation implies it tries to parse as much as possible.
                    // On error, the remaining string isn't clearly defined by the API for partial success.
                    // Returning "" simplifies error handling upstream, assuming the error applies to the whole input string.
            );
        }

        // If parse was successful
        if is_command {
            if !parse_struct.commandStart.is_null() {
                let command_start_offset = parse_struct.commandStart as usize - string_start_addr;
                if command_start_offset <= string.len() { // Bounds check
                    let prefix_to_command = &string[0..command_start_offset];
                    calculated_line_number = 1 + prefix_to_command.matches('\n').count();
                }
            } else {
                // commandStart is null on successful parse. This can happen if \'string\' is empty
                // or contains only comments/whitespace that Tcl_ParseCommand skips entirely
                // before finding any command. In such cases, commandSize would be 0.
                // The line number relative to \'string\' is 1.
                calculated_line_number = 1;
            }
        }
        // For expressions (is_expr = true), calculated_line_number remains 1 (relative to the expression string itself)

        let tokens = make_tokens(string, string_start_addr, &parse_struct);

        let (tclparse_result, remaining_str) = match (is_command, is_expr) {
            (true, false) => {
                assert!(tokens.len() == parse_struct.numWords as usize);
                let comment_str = Some(match parse_struct.commentSize as usize {
                    0 => "",
                    l => {
                        let offset = parse_struct.commentStart as usize - string_start_addr;
                        &string[offset..offset + l]
                    }
                });
                let command_len = parse_struct.commandSize as usize;
                let command_off = parse_struct.commandStart as usize - string_start_addr;
                let command_val = Some(&string[command_off..command_off + command_len]);
                let remaining_after_command = &string[command_off + command_len..];
                (
                    TclParse {
                        comment: comment_str,
                        command: command_val,
                        tokens: tokens,
                        line_number: calculated_line_number,
                    },
                    remaining_after_command,
                )
            }
            (false, true) => (
                TclParse {
                    comment: None,
                    command: None,
                    tokens: tokens,
                    line_number: 1, // Expressions are parsed as a single unit, line is 1 relative to expr string
                },
                "", // Tcl_ParseExpr consumes the whole string or errors
            ),
            _ => panic!("UNPARSABLE: Unreachable state after successful parse"),
        };

        tcl::Tcl_FreeParse(parse_ptr);
        return (tclparse_result, remaining_str);
    }
}

unsafe fn make_tokens<'a>(
    string: &'a str,
    string_start: usize,
    tcl_parse: &tcl::Tcl_Parse,
) -> Vec<TclToken<'a>> { unsafe {
    let mut acc = vec![];
    for i in (0..tcl_parse.numTokens as isize).rev() {
        let tcl_token = *(tcl_parse.tokenPtr).offset(i);
        assert!(tcl_token.start as usize > 0);
        let offset = tcl_token.start as usize - string_start;
        let token_size = tcl_token.size as usize;
        let tokenval = &string[offset..offset + token_size];
        make_tcltoken(&tcl_token, tokenval, &mut acc);
    }
    acc.reverse();
    return acc;
}}

fn count_tokens(token: &TclToken) -> usize {
    token.tokens.iter().map(|t| count_tokens(t)).sum::<usize>() + 1
}

fn make_tcltoken<'a>(tcl_token: &tcl::Tcl_Token, tokenval: &'a str, acc: &mut Vec<TclToken<'a>>) {
    let token_type: TokenType = TokenType::from_usize(tcl_token.type_ as usize).unwrap();
    let num_subtokens = tcl_token.numComponents as usize;

    let subtokens = match token_type {
        Word | ExpandWord => {
            let mut subtokens = vec![];
            let mut count = 0;
            while count < num_subtokens {
                assert!(acc.len() > 0);
                let tok = acc.pop().unwrap();
                count += count_tokens(&tok);
                subtokens.push(tok);
            }
            assert!(count == num_subtokens);
            subtokens
        }
        SimpleWord => {
            assert!(acc.len() > 0);
            assert!(num_subtokens == 1);
            let tok = acc.pop().unwrap();
            assert!(tok.ttype == Text);
            vec![tok]
        }
        Text | Bs => {
            assert!(num_subtokens == 0);
            vec![]
        }
        Command => {
            assert!(tokenval.chars().nth(0) == Some('['));
            assert!(num_subtokens == 0);
            vec![]
        }
        Variable => {
            assert!(acc.len() > 0);
            let tok = acc.pop().unwrap();
            assert!(tok.ttype == Text);
            let mut subtokens = vec![tok];
            let mut count = 1;
            while count < num_subtokens {
                assert!(acc.len() > 0);
                let tok = acc.pop().unwrap();
                count += match tok.ttype {
                    Text | Bs | Command | Variable => count_tokens(&tok),
                    _ => panic!("ERROR: Invalid token type {:?}", tok.ttype),
                };
                subtokens.push(tok);
            }
            assert!(count == num_subtokens);
            subtokens
        }
        SubExpr => {
            assert!(acc.len() > 0);
            let start_ttype = acc[acc.len() - 1].ttype;
            let mut subtokens = vec![];
            let mut count = 0;
            if start_ttype == Operator {
                subtokens.push(acc.pop().unwrap());
                count += 1;
            }
            while count < num_subtokens {
                assert!(acc.len() > 0);
                let tok = acc.pop().unwrap();
                if start_ttype == Operator {
                    assert!(tok.ttype == SubExpr);
                }
                match tok.ttype {
                    Word | Text | Bs | Command | Variable | SubExpr => count += count_tokens(&tok),
                    _ => panic!("ERROR: Invalid token {:?}", tok.ttype),
                }
                subtokens.push(tok);
            }
            assert!(count == num_subtokens);
            subtokens
        }
        Operator => {
            if acc.is_empty() {
                panic!("ERROR: Invalid Operator token {:?}", tokenval)
            }
            assert!(num_subtokens == 0);
            vec![]
        }
    };
    acc.push(TclToken {
        val: tokenval,
        tokens: subtokens,
        ttype: token_type,
    })
}
