#![feature(libc)]
#![feature(rustc_private)]

extern crate libc;
// https://github.com/rust-lang/rust/issues/16920
#[macro_use]
extern crate enum_primitive;

use self::CheckResult::*;
use fancy_regex::Regex;
use rstcl::TokenType;
use std::fmt;
use std::iter;
use serde_json::json;

pub mod rstcl;
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
mod tcl;

#[derive(PartialEq)]
pub enum CheckResult<'a> {
    // context, message, problem code, line_number
    Warn(&'a str, &'static str, &'a str, usize),
    Danger(&'a str, &'static str, &'a str, usize),
}
impl<'b> fmt::Display for CheckResult<'b> {
    fn fmt<'a>(&'a self, f: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            &Warn(ctx, msg, code, line_num) => write!(
                f,
                "WARNING: (L{}) {} at `{}` in `{}`",
                line_num,
                msg,
                code,
                ctx.replace("\n", "")
            ),
            &Danger(ctx, msg, code, line_num) => write!(
                f,
                "DANGEROUS: (L{}) {} at `{}` in `{}`",
                line_num,
                msg,
                code,
                ctx.replace("\n", "")
            ),
        };
    }
}

#[derive(Clone)]
enum Code {
    Block,
    Expr,
    Literal,
    Normal,
    SwitchBody,
}

fn check_literal<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>, line_number: usize) -> Vec<CheckResult<'a>> {
    let token_str = token.val;
    assert!(token_str.len() > 0);
    return if token_str.chars().nth(0) == Some('{') {
        vec![]
    } else if token_str.contains('$') {
        vec![Danger(ctx, "Expected literal, found $", token_str, line_number)]
    } else if token_str.contains('[') {
        vec![Danger(ctx, "Expected literal, found [", token_str, line_number)]
    } else {
        vec![]
    };
}

// Does this variable only contain safe characters?
// Only used by is_safe_val
fn is_safe_var(token: &rstcl::TclToken) -> bool {
    assert!(token.ttype == TokenType::Variable);
    return false;
}

// Does the return value of this function only contain safe characters?
// Only used by is_safe_val.
// Line number is not directly applicable here as it's about the nature of the command,
// but if we were to report, it would be the line of `token`.
fn is_safe_cmd(token: &rstcl::TclToken) -> bool {
    let string = token.val;
    assert!(string.starts_with("[") && string.ends_with("]"));
    let script = &string[1..string.len() - 1];
    let parses = rstcl::parse_script(script);
    // Empty script
    if parses.len() == 0 {
        return true;
    }
    // If parses[0] itself has a line_number, it's relative to `script`.
    // The line_number of `token` (the `[...]` itself) is the relevant one for the outer context.
    let token_strs: Vec<&str> = parses[0].tokens.iter().map(|e| e.val).collect();
    return match &token_strs[..] {
        ["llength", _] | ["clock", "seconds"] | ["info", "exists", ..] | ["catch", ..] => true,
        _ => false,
    };
}

// Check whether a value can ever cause or assist in any security flaw i.e.
// whether it may contain special characters.
// We do *not* concern ourselves with vulnerabilities in sub-commands. That
// should happen elsewhere.
fn is_safe_val(token: &rstcl::TclToken) -> bool {
    assert!(token.val.len() > 0);
    for tok in token.iter() {
        let is_safe = match tok.ttype {
            TokenType::Variable => is_safe_var(tok),
            TokenType::Command => is_safe_cmd(tok),
            _ => true,
        };
        if !is_safe {
            return false;
        }
    }
    return true;
}

// Helper function to check for non-standard ASCII characters in a token and its sub-tokens
fn check_token_characters<'a>(
    ctx: &'a str,
    token: &rstcl::TclToken<'a>,
    command_line_number: usize,
) -> Vec<CheckResult<'a>> {
    let mut warnings = Vec::new();

    // Check the current token's value
    for ch in token.val.chars() {
        let is_allowed_char = (ch >= '\u{0020}' && ch <= '\u{007E}') || // ASCII printable and space
                               ch == '\t' || // Tab
                               ch == '\n' || // Newline
                               ch == '\r'; // Carriage Return

        if !is_allowed_char {
            warnings.push(CheckResult::Warn(
                ctx,
                "Token contains character(s) outside the standard ASCII printable/whitespace set",
                token.val, // The problematic token's value
                command_line_number, // Use the command's line number for this warning
            ));
            break; // Add only one warning per token value to avoid flooding
        }
    }

    // Recursively check sub-tokens. The line number context remains that of the original command.
    for sub_token in token.tokens.iter() {
        warnings.extend(check_token_characters(ctx, sub_token, command_line_number));
    }

    warnings
}

pub fn check_command<'a, 'b>(
    ctx: &'a str,
    tokens: &'b Vec<rstcl::TclToken<'a>>,
    line_number: usize, // Line number of the command itself
) -> Vec<CheckResult<'a>> {
    let mut results = vec![];

    // Add the character set check for all tokens in the command
    for token in tokens.iter() {
        results.extend(check_token_characters(ctx, token, line_number));
    }

    // First check all subcommands which will be substituted
    // The line number for these subcommands is the line of the main command.
    // A more precise line number for the subcommand itself (if it spans multiple lines)
    // is not easily available here without deeper parsing of token.val for Command tokens.
    // For now, attribute to the line of the containing command.
    for tok in tokens.iter() {
        for subtok in tok.iter().filter(|t| t.ttype == TokenType::Command) {
            // scan_command expects the line number of the script it's scanning.
            // Since subtok.val is like "[...]", its content starts on "line 1" relative to itself.
            // However, the *location* of this [...] is `line_number`.
            // We pass `line_number` to `scan_command` which will then be used if `scan_script` inside it
            // generates findings.
            results.extend(scan_command(subtok.val, line_number).into_iter());
        }
    }
    // The empty command (caused by e.g. `[]`, `;;`, last parse in a script)
    if tokens.len() == 0 {
        return results;
    }
    // Now check if the command name itself isn't a literal
    // The line number for this check is the line of the command.
    if check_literal(ctx, &tokens[0], line_number).into_iter().len() > 0 {
        results.push(Warn(ctx, "Non-literal command, cannot scan", tokens[0].val, line_number));
        return results;
    }
    // Now check the command-specific interpretation of arguments etc
    let param_types = match tokens[0].val {
        // tmconf: ltm rule <name> { }
        "ltm" => vec![Code::Literal, Code::Literal, Code::Block],
        // tmconf: rule <name> { }
        "rule" => vec![Code::Literal, Code::Block],
        // iRule when
        "when" => match tokens.len() {
            // when <event_name> [priority N] {}
            // when <event_name> [timing on|off] {}
            5 => vec![Code::Literal, Code::Literal, Code::Literal, Code::Block],
            // when <event_name> [timing on|off] [priority N] {}
            7 => vec![
                Code::Literal,
                Code::Literal,
                Code::Literal,
                Code::Literal,
                Code::Literal,
                Code::Block,
            ],
            // when <event_name> {}
            _ => vec![Code::Literal, Code::Block],
        },
        // eval script
        "eval" => iter::repeat(Code::Block).take(tokens.len() - 1).collect(),
        // tcl8.4: catch script ?varName?
        "catch" => {
            let mut param_types = vec![Code::Block];
            if tokens.len() == 3 {
                let new_params: Vec<Code> =
                    iter::repeat(Code::Literal).take(tokens.len() - 2).collect();
                param_types.extend_from_slice(&new_params);
            }
            param_types
        }
        // expr [arg]+
        "expr" => tokens[1..].iter().map(|_| Code::Expr).collect(),
        // proc name args body
        "proc" => vec![Code::Literal, Code::Literal, Code::Block],
        // for init cond iter body
        "for" => vec![Code::Block, Code::Expr, Code::Block, Code::Block],
        // foreach varlist1 list1 ?varlist2 list2 ...? body
        "foreach" => {
            let mut param_types = vec![Code::Literal, Code::Normal];
            if tokens.len() > 4 {
                // foreach {i y} {a b c d} j {d e f g} { }
                let mut i = 2;
                while i < tokens.len() - 1 {
                    param_types.extend_from_slice(&vec![Code::Literal, Code::Normal]);
                    i = param_types.len() + 2;
                }
            }
            param_types.extend_from_slice(&vec![Code::Block]);
            param_types
        }
        // while cond body
        "while" => vec![Code::Expr, Code::Block],
        // if cond body [elseif cond body]* [else body]?
        // iRules allow elseif to start on new line
        "if" | "elseif" => {
            let mut param_types = vec![Code::Expr];
            let mut i = 2;
            while i < tokens.len() {
                param_types.extend_from_slice(&match tokens[i].val {
                    "then" => vec![Code::Literal],
                    "elseif" => {
                        if tokens[i + 2].val == "then" {
                            vec![Code::Literal, Code::Expr, Code::Literal, Code::Block]
                        } else {
                            vec![Code::Literal, Code::Expr, Code::Block]
                        }
                    }
                    "else" => vec![Code::Literal, Code::Block],
                    _ => vec![Code::Block],
                });
                i = param_types.len() + 1;
            }
            param_types
        }
        // iRules allow else to start on new line
        "else" => vec![Code::Block],
        //regexp|regsub : expression in this case refers to regular expression not tcl expressions
        //list: list itself doesn't treat its arguments as anything in particular, but it does format them into items in a list. In a list, \ " and { operate the same way they do in Tcl. Tcl is designed this way so that a list is a properly-formatted command.
        //set: ( accesses a variable in an array.
        //string match: *, ?, [, and \ have special meaning.
        "auto_execok" | "auto_import" | "auto_load" | "auto_mkindex" | "auto_mkindex_old"
        | "auto_qualify" | "auto_reset" | "bgerror" | "cd" | "dict" | "encoding" | "eof"
        | "exec" | "exit" | "fblocked" | "fconfigure" | "fcopy" | "file" | "fileevent"
        | "filename" | "flush" | "gets" | "glob" | "http" | "interp" | "load" | "lrepeat"
        | "lreverse" | "memory" | "namespace" | "open" | "package" | "pid" | "pkg_mkIndex"
        | "pkg::create" | "pwd" | "rename" | "seek" | "socket" | "source" | "tcl_findLibrary"
        | "tell" | "time" | "trace" | "unknown" | "update" => {
            results.push(Warn(ctx, "command unsupported", tokens[0].val, line_number));
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        "uplevel" | "history" => {
            results.push(Danger(ctx, "command unsafe", tokens[0].val, line_number));
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        // deprecated iRule commands
        "accumulate" | "client_addr" | "client_port" | "decode_uri" | "findclass"
        | "http_cookie" | "http_header" | "http_host" | "http_method" | "http_uri"
        | "http_version" | "imid" | "ip_addr" | "ip_protocol" | "ip_tos" | "ip_ttl"
        | "link_qos" | "local_addr" | "local_port" | "matchclass" | "redirect" | "remote_addr"
        | "remote_port" | "server_addr" | "server_port" | "urlcatblindquery" | "urlcatquery"
        | "use" | "vlan_id" => {
            results.push(Warn(ctx, "command deprecated", tokens[0].val, line_number));
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        "after" => match tokens[1].val {
            "cancel" | "info" => {
                // after cancel|info 123
                // after cancel|info {123 987}
                // after cancel|info [list 12 34 56]
                if !(tokens[1].val == "cancel" && tokens[2].val == "-current") {
                    vec![Code::Literal, Code::Normal]
                } else {
                    // after cancel -current
                    vec![Code::Literal, Code::Literal]
                }
            }
            _ => match tokens.len() {
                // after <ms>
                2 => vec![Code::Normal],
                // after <ms> < script >
                3 => vec![Code::Normal, Code::Block],
                // after <ms> [-periodic] < script >
                _ => vec![Code::Normal, Code::Literal, Code::Block],
            },
        },
        // switch ?options? string pattern body ?pattern body …?
        //               options: -exact -glob -regexp --
        // switch -exact -glob -regexp --
        // switch -exact -glob -regexp -- string {switch_block}
        "switch" => {
            let mut options_terminated = false;
            let mut i = 1;
            let mut param_types: Vec<Code> = vec![];
            while i < tokens.len() {
                match tokens[i].val {
                    "-exact" | "-glob" | "-regexp" => {
                        param_types.extend_from_slice(&vec![Code::Literal]);
                        i += 1;
                    }
                    "--" => {
                        param_types.extend_from_slice(&vec![Code::Literal]);
                        options_terminated = true;
                        i += 1;
                        break;
                    }
                    _ => {
                        break;
                    }
                };
            }
            if !options_terminated {
                results.push(Danger(
                    ctx,
                    "missing options terminator `--` permits argument injection",
                    tokens[i].val, line_number // Line of the switch command
                ));
            }
            // The check for "Dangerous unquoted switch body" refers to the structure of the switch command's arguments.
            // If tokens[i] is the string argument, its line number is implicitly that of the overall command.
            // If the body (tokens[i+1]) is problematic, it's still part of this command line.
            if (tokens.len() - i) != 2 { // This check might be too simplistic for line numbers if args are on new lines
                results.push(Danger(ctx, "dangerous switch body, use braces `{ .. }`", tokens[i].val, line_number));
            }
            param_types.extend_from_slice(&vec![Code::Normal, Code::SwitchBody]);
            param_types
        }
        // class search [-index -name -value -element -all --] <class> <operator> <item>
        // class match [-index -name -value -element -all --] <item> <operator> <class>
        // class nextelement [-index -name -value --] <class> <search_id>
        // class element [-name -value --] <index> <class>
        "class" => {
            let tokens_total_len = match tokens[1].val {
                "search" | "match" => tokens.len() - 3,
                _ => tokens.len() - 2,
            };
            let mut options_terminated = match tokens[1].val {
                "search" | "match" | "nextelement" | "element" => false,
                _ => true,
            };
            let mut i = 2;
            while i < tokens_total_len {
                if tokens[i].val == "--" {
                    options_terminated = true;
                    break;
                }
                i += 1;
            }
            if !options_terminated {
                results.push(Danger(
                    ctx,
                    "missing options terminator `--` permits argument injection",
                    tokens[i].val, line_number // Line of the class command
                ));
            }
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        //unset -nocomplain -- var1 ?var2?
        "unset" => {
            let mut pos = 0;
            if tokens[1].val == "-nocomplain" {
                if tokens[2].val != "--" {
                    pos = 2;
                }
            } else if tokens[1].val != "--" {
                pos = 1;
            }
            if pos > 0 {
                results.push(Danger(
                    ctx,
                    "missing options terminator `--` permits argument injection",
                    tokens[pos].val, line_number // Line of the unset command
                ));
            }
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        //regexp -about -expanded -indices -line -linestop -lineanchor -nocase -all -inline -start <index> --
        //regsub -all -expanded -line -linestop -lineanchor -nocase -start <index> --
        "regexp" | "regsub" => {
            let mut options_terminated = false;
            let mut i = 1;
            while i < tokens.len() {
                match tokens[i].val {
                    "-about" | "-all" | "-expanded" | "-indices" | "-inline" | "-line"
                    | "-lineanchor" | "-linestop" | "-nocase" => {
                        i += 1;
                    }
                    "-start" => {
                        i += 2;
                    }
                    "--" => {
                        options_terminated = true;
                        break;
                    }
                    _ => {
                        break;
                    }
                };
            }
            if !options_terminated {
                results.push(Danger(
                    ctx,
                    "missing options terminator `--` permits argument injection",
                    tokens[i].val, line_number // Line of the regexp/regsub command
                ));
            }
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        // table set      [-notouch] [-subtable <name> | -georedundancy] [-mustexist|-excl] <key> <value> [<timeout> [<lifetime>]]
        // table add      [-notouch] [-subtable <name> | -georedundancy] <key> <value> [<timeout> [<lifetime>]]
        // table replace  [-notouch] [-subtable <name> | -georedundancy] <key> <value> [<timeout> [<lifetime>]]
        // table lookup   [-notouch] [-subtable <name> | -georedundancy] <key>
        // table incr     [-notouch] [-subtable <name> | -georedundancy] [-mustexist] <key> [<delta>]
        // table append   [-notouch] [-subtable <name> | -georedundancy] [-mustexist] <key>  <string>
        // table delete   [-subtable <name> | -georedundancy] <key>|-all
        // table timeout  [-subtable <name> | -georedundancy] [-remaining] <key>
        // table timeout  [-subtable <name> | -georedundancy] <key> [<value>]
        // table lifetime [-subtable <name> | -georedundancy] [-remaining] <key>
        // table lifetime [-subtable <name> | -georedundancy] <key> [<value>]
        // table keys -subtable <name> [-count|-notouch]
        "table" => {
            let mut options_terminated = false;
            let mut i = 1;
            while i < tokens.len() {
                match tokens[i].val {
                    "set" | "add" | "replace" | "lookup" | "incr" | "append" | "delete"
                    | "timeout" | "lifetime" | "-notouch" | "-georedundancy" | "-mustexist"
                    | "-count" | "-remaining" | "-excl" => {
                        i += 1;
                    }
                    "-subtable" => {
                        i += 2;
                    }
                    "keys" => {
                        options_terminated = true;
                        break;
                    }
                    "--" => {
                        options_terminated = true;
                        break;
                    }
                    _ => {
                        break;
                    }
                };
            }
            if !options_terminated {
                results.push(Danger(
                    ctx,
                    "missing options terminator `--` permits argument injection",
                    tokens[i].val, line_number // Line of the table command
                ));
            }
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        // default
        _ => iter::repeat(Code::Normal).take(tokens.len() - 1).collect(),
    };
    if param_types.len() != tokens.len() - 1 {
        results.push(Danger(
            ctx,
            "badly formed command, cannot scan code",
            tokens[0].val, line_number // Line of the command
        ));
        return results;
    }
    for (param_type, param) in param_types.iter().zip(tokens[1..].iter()) {
        // The `param` token is part of the current command. Its line number for reporting
        // issues directly related to it (like unquoted literal) is `line_number`.
        // If it\'s a block/expr that gets scanned recursively, the line numbers *inside* that
        // block will be relative to the start of the block\'s content.
        let check_results: Vec<CheckResult<'a>> = match *param_type {
            Code::Block => check_block(ctx, param, line_number), // Pass current command\'s line as base for block
            Code::SwitchBody => check_switch_body(ctx, param, line_number), // Same for switch body
            Code::Expr => check_expr(ctx, param, line_number), // Same for expr
            Code::Literal => check_literal(ctx, param, line_number), // Literal check uses current command\'s line
            Code::Normal => vec![],
        };
        results.extend(check_results.into_iter());
    }
    return results;
}

/// Scans a switch body (i.e. should be quoted) for danger
// base_line_number is the line number of the `switch` command itself.
fn check_switch_body<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>, base_line_number: usize) -> Vec<CheckResult<'a>> {
    let body_str = token.val;
    if !(body_str.starts_with("{") && body_str.ends_with("}")) {
        // This finding is about the switch body token itself, so use base_line_number
        return vec![Danger(ctx, r#"dangerous unsafe switch body, use braces `{ .. }`"#, body_str, base_line_number)];
    }
    // Body isn't inherently dangerous, let's check body elements
    let script_str = &body_str[1..body_str.len() - 1];

    let mut all_results: Vec<CheckResult<'a>> = vec![];
    // `rstcl::parse_script` will give line numbers relative to `script_str` (which starts at line 1).
    // we need to adjust these by `base_line_number` and account for the `{` character.
    // The content of script_str effectively starts on the same line as the opening `{` of the token
    // If token.val is "{...}", its line is base_line_number
    for parse_item in rstcl::parse_script(script_str) {
        let item_line_number_in_block = parse_item.line_number; // 1-based relative to script_str
        // The line number is base_line_number + (item_line_number_in_block - 1)
        // because script_str starts on base_line_number.
        let actual_line_number = base_line_number + item_line_number_in_block -1;

        let mut i = 0;
        for inner_token in parse_item.tokens.iter() {
            if i % 2 == 0 || inner_token.val == "-" {
                // every 1st token is a Literal
                let results = check_literal(ctx, inner_token, actual_line_number); // Line of the pattern
                all_results.extend(results.into_iter());
            } else {
                // every 2nd token is a block unless it is a dash
                // The `inner_token` (block) starts at `actual_line_number`.
                let results = check_block(ctx, inner_token, actual_line_number);
                all_results.extend(results.into_iter());
            }
            i += 1;
        }
    }
    return all_results;
}

/// Scans a block (i.e. should be quoted) for danger
// base_line_number is the line number in the original script where this block token starts.
fn check_block<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>, base_line_number: usize) -> Vec<CheckResult<'a>> {
    let block_str = token.val;
    if !(block_str.starts_with("{") && block_str.ends_with("}")) {
        // finding is about the code block token itself, so use base_line_number
        return vec![match is_safe_val(token) {
            true => Warn(ctx, "unsafe code block, use braces `{ .. }`", block_str, base_line_number),
            false => Danger(ctx, "dangerous unsafe code block, use braces `{ .. }`", block_str, base_line_number),
        }];
    }
    // Block isn\'t inherently dangerous, let\'s check functions inside the block
    let script_str = &block_str[1..block_str.len() - 1];
    // scan_script needs the starting line number of script_str.
    // If token.val is \"{}\", its line is base_line_number. The content inside also starts there.
    return scan_script_recursive(script_str, base_line_number);
}

/// Scans an expr (i.e. should be quoted) for danger
// base_line_number is the line number in the original script where this expr token starts.
fn check_expr<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>, base_line_number: usize) -> Vec<CheckResult<'a>> {
    let mut results = vec![];
    let expr_str = token.val;
    if !(expr_str.starts_with("{") && expr_str.ends_with("}")) {
        // This finding is about the expr token itself, so use base_line_number
        results.push(match is_safe_val(token) { // is_safe_val doesn\'t use line_number
            true => Warn(ctx, "unsafe expression, use braces `{ .. }`", expr_str, base_line_number),
            false => Danger(ctx, "dangerous unsafe expression, use braces `{ .. }`", expr_str, base_line_number),
        });
        return results;
    };
    // Expr isn\'t inherently dangerous, let\'s check functions inside the expr
    assert!(token.val.starts_with("{") && token.val.ends_with("}"));
    let expr_content_str = &token.val[1..token.val.len() - 1];
    let (parse_result, remaining) = rstcl::parse_expr(expr_content_str); // parse_expr gives line_number 1 for the expression itself.
    assert!(parse_result.tokens.len() == 1 && remaining == ""); // Assuming parse_expr consumes all or errors.

    // The line_number from parse_result is 1 (relative to expr_content_str).
    // Commands inside this expression will be on base_line_number + (relative_line_of_command_in_expr - 1).
    // Since Tcl_ParseExpr treats the whole thing as one, sub-commands effectively start at line 1 of the expr content.
    // So, their effective line is base_line_number.
    for tok_in_expr in parse_result.tokens[0]
        .iter()
        .filter(|t| t.ttype == TokenType::Command)
    {
        // tok_in_expr.val is like \"[sub_script]\". scan_command needs the line number where this \"[...]\" occurs.
        // This is base_line_number.
        results.extend(scan_command(tok_in_expr.val, base_line_number).into_iter());
    }
    return results;
}

/// Scans a TokenType::Command token (contained in '[]') for danger
// outer_line_number is the line number in the original script where this command token `string` (e.g. \"[...]\") starts.
pub fn scan_command<'a>(string: &'a str, outer_line_number: usize) -> Vec<CheckResult<'a>> {
    assert!(string.starts_with("[") && string.ends_with("]"));
    let script_content = &string[1..string.len() - 1];
    // The content of the script_content starts at outer_line_number.
    return scan_script_recursive(script_content, outer_line_number);
}

/// Scans a sequence of commands for danger.
/// base_line_number_offset is the 1-based line number in the original, top-level script
/// where `string_segment` begins.
pub fn scan_script_recursive<'a>(string_segment: &'a str, base_line_number_offset: usize) -> Vec<CheckResult<'a>> {
    let mut all_results: Vec<CheckResult<'a>> = vec![];
    for parse in rstcl::parse_script(string_segment) {
        // parse.line_number is already absolute with respect to string_segment (1-based).
        // We need to adjust it to be absolute with respect to the original top-level script.
        let absolute_line_num = base_line_number_offset + parse.line_number -1;
        let results = check_command(&parse.command.unwrap_or(""), &parse.tokens, absolute_line_num);
        all_results.extend(results.into_iter());
    }
    return all_results;
}

/// Top-level scan function.
pub fn scan_script<'a>(script: &'a str) -> Vec<CheckResult<'a>> {
    // For the top-level script, the base line number offset is 1.
    // rstcl::parse_script will return line numbers relative to the start of `script`.
    // So, if a command is on line `N` of `script`, its `parse.line_number` will be `N`.
    // This `N` is already the absolute line number we want.
    let mut all_results: Vec<CheckResult<'a>> = vec![];
    for parse in rstcl::parse_script(script) {
        // parse.line_number is the absolute 1-based line number from rstcl.
        let results = check_command(&parse.command.unwrap_or(""), &parse.tokens, parse.line_number);
        all_results.extend(results.into_iter());
    }
    return all_results;
}

/// Preprocess iRules to sanitize lax irule syntax
pub fn preprocess_script(string: &str) -> String {
    fn re_replacer(s: &str, re: &Regex, t: &str) -> String {
        re.replace_all(s, t).into()
    }
    let processed_script = &string;
    //let processed_script = re_replacer(
    //    &processed_script,
    //    &Regex::new(r"(?<=[^\\])\\\s+\n").unwrap(),
    //    &r"\\\n"
    //);
    // HACK: rand() causes parsing errors, to avoid backtraces inject artificial parameter
    let processed_script = re_replacer(
        &processed_script,
        &Regex::new(r"rand\(\)").unwrap(),
        &r"rand(1)",
    );
    // format according to tcl syntax, iRules are too lax
    let processed_script = re_replacer(
        &processed_script,
        &Regex::new(r"(?<!(\\|\{))\n[\s]*\{").unwrap(),
        &" {\n", // add newline to retain line numbers
    );
    // format according to tcl syntax, iRules are too lax
    let processed_script = re_replacer(
        &processed_script,
        //&Regex::new(r"(?P<token>\}|else|then|while|for)[\n\s]*\{").unwrap(),
        &Regex::new(r"(?P<token>\}|else|then|while|for)\n[\s]*\{").unwrap(),
        &"$token {\n", // add newline to retain line numbers
    );
    return processed_script;
}

pub fn scan_and_format_results(
    preprocessed_scripts: &Vec<(String, String)>,
    no_warn: bool,
    exclude_empty_findings: bool,
) -> serde_json::Value {
    let mut result_list = Vec::new();

    for (path, script) in preprocessed_scripts.iter() {
        let mut res = scan_script(&script); // scan_script is the top-level entry

        // filter out warnings if --no-warn flag is set
        if no_warn {
            res = res
                .into_iter()
                .filter(|r| match r {
                    &CheckResult::Warn(_, _, _, _) => false,
                    _ => true,
                })
                .collect();
        }

        let mut warning_objects = Vec::new();
        let mut dangerous_objects = Vec::new();

        if res.len() > 0 {
            for check_result in res.iter() {
                match check_result {
                    &CheckResult::Warn(ref ctx, ref msg, ref code, line_num) => {
                        let mut context_str = ctx.replace("\n", "");
                        if context_str.len() > 200 {
                            context_str.truncate(200);
                            context_str.push_str(" <truncated>");
                        }
                        warning_objects.push(json!({
                            "message": msg,
                            "issue_location": code,
                            "context": context_str,
                            "line": line_num
                        }));
                    }
                    &CheckResult::Danger(ref ctx, ref msg, ref code, line_num) => {
                        let mut context_str = ctx.replace("\n", "");
                        if context_str.len() > 200 {
                            context_str.truncate(200);
                            context_str.push_str(" <truncated>");
                        }
                        dangerous_objects.push(json!({
                            "message": msg,
                            "issue_location": code,
                            "context": context_str,
                            "line": line_num
                        }));
                    }
                }
            }
        };

        if exclude_empty_findings && warning_objects.len() == 0 && dangerous_objects.len() == 0 {
            continue;
        }

        let json_entries = json!({
            "filepath": path,
            "warning": warning_objects,
            "dangerous": dangerous_objects
        });
        let _ = result_list.push(json_entries);
    }

    return serde_json::json!(result_list);
}