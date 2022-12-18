#![feature(libc)]
#![feature(rustc_private)]

extern crate libc;
// https://github.com/rust-lang/rust/issues/16920
#[macro_use] extern crate enum_primitive;
extern crate num;

use std::iter;
use std::fmt;
use self::CheckResult::*; // TODO: why does swapping this line with one below break?
use rstcl::TokenType;

pub mod rstcl;
#[allow(dead_code, non_upper_case_globals, non_camel_case_types, non_snake_case)]
mod tcl;

#[derive(PartialEq)]
pub enum CheckResult<'a> {
    // context, message, problem code
    Warn(&'a str, &'static str, &'a str),
    Danger(&'a str, &'static str, &'a str),
}
impl<'b> fmt::Display for CheckResult<'b> {
    fn fmt<'a>(&'a self, f: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            &Warn(ctx, msg, line) => write!(f, "WARNING: {} at `{}` in `{}`", msg, line, ctx.replace("\n", "")),
            &Danger(ctx, msg, line) => write!(f, "DANGEROUS: {} at `{}` in `{}`", msg, line, ctx.replace("\n", "")),
        };
    }
}

#[derive(Clone)]
enum Code {
    Block,
    Expr,
    Literal,
    Normal,
}

fn check_literal<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>) -> Vec<CheckResult<'a>> {
    let token_str = token.val;
    assert!(token_str.len() > 0);
    return if token_str.chars().nth(0) == Some('{') {
        vec![]
    } else if token_str.contains('$') {
        vec![Danger(ctx, "Expected literal, found $", token_str)]
    } else if token_str.contains('[') {
        vec![Danger(ctx, "Expected literal, found [", token_str)]
    } else {
        vec![]
    }
}

// Does this variable only contain safe characters?
// Only used by is_safe_val
fn is_safe_var(token: &rstcl::TclToken) -> bool {
    assert!(token.ttype == TokenType::Variable);
    return false
}

// Does the return value of this function only contain safe characters?
// Only used by is_safe_val.
fn is_safe_cmd(token: &rstcl::TclToken) -> bool {
    let string = token.val;
    assert!(string.starts_with("[") && string.ends_with("]"));
    let script = &string[1..string.len()-1];
    let parses = rstcl::parse_script(script);
    // Empty script
    if parses.len() == 0 {
        return true;
    }
    let token_strs: Vec<&str> = parses[0].tokens.iter().map(|e| e.val).collect();
    return match &token_strs[..] {
        ["llength", _] |
        ["clock", "seconds"] |
        ["info", "exists", ..] |
        ["catch", ..] => true,
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

pub fn check_command<'a, 'b>(ctx: &'a str, tokens: &'b Vec<rstcl::TclToken<'a>>) -> Vec<CheckResult<'a>> {
    let mut results = vec![];
    // First check all subcommands which will be substituted
    for tok in tokens.iter() {
        for subtok in tok.iter().filter(|tok| tok.ttype == TokenType::Command) {
            results.extend(scan_command(subtok.val).into_iter());
        }
    }
    // The empty command (caused by e.g. `[]`, `;;`, last parse in a script)
    if tokens.len() == 0 {
        return results;
    }
    // Now check if the command name itself isn't a literal
    if check_literal(ctx, &tokens[0]).into_iter().len() > 0 {
        results.push(Warn(ctx, "Non-literal command, cannot scan", tokens[0].val));
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
                7 => vec![Code::Literal, Code::Literal, Code::Literal, Code::Literal, Code::Literal, Code::Block],
                // when <event_name> {}
                _ => vec![Code::Literal, Code::Block],
        },
        // eval script
        "eval" => iter::repeat(Code::Block).take(tokens.len()-1).collect(),
        // tcl8.4: catch script ?varName?
        "catch" => {
            let mut param_types = vec![Code::Block];
            if tokens.len() == 3 {
                let new_params: Vec<Code> = iter::repeat(Code::Literal).take(tokens.len()-2).collect();
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
                while i < tokens.len()-1 {
                    param_types.extend_from_slice(&vec![Code::Literal, Code::Normal]);
                    i = param_types.len() + 2;
                }
            }
            param_types.extend_from_slice(&vec![Code::Block]);
            param_types
        },
        // while cond body
        "while" => vec![Code::Expr, Code::Block],
        // if cond body [elseif cond body]* [else body]?
        // iRules allow elseif to start on new line
        "if"|"elseif" => {
            let mut param_types = vec![Code::Expr];
            let mut i = 2;
            while i < tokens.len() {
                param_types.extend_from_slice(&match tokens[i].val {
                    "then" => vec![Code::Literal],
                    "elseif" => {
                        if tokens[i+2].val == "then" {
                            vec![Code::Literal, Code::Expr, Code::Literal, Code::Block]
                        } else {
                            vec![Code::Literal, Code::Expr, Code::Block]
                        }
                    },
                    "else" => vec![Code::Literal, Code::Block],
                    _ => vec![Code::Block],
                });
                i = param_types.len() + 1;
            }
            param_types
        },
        // iRules allow else to start on new line
        "else" => vec![Code::Block],
        //regexp|regsub : expression in this case refers to regular expression not tcl expressions
        //list: list itself doesn't treat its arguments as anything in particular, but it does format them into items in a list. In a list, \ " and { operate the same way they do in Tcl. Tcl is designed this way so that a list is a properly-formatted command.
        //set: ( accesses a variable in an array.
        //string match: *, ?, [, and \ have special meaning.
        "auto_execok"|"auto_import"|"auto_load"|"auto_mkindex"|"auto_mkindex_old"|"auto_qualify"|"auto_reset"|"bgerror"|"cd"|"dict"|
        "encoding"|"eof"|"exec"|"exit"|"fblocked"|"fconfigure"|"fcopy"|"file"|"fileevent"|"filename"|"flush"|
        "gets"|"glob"|"http"|"interp"|"load"|"lrepeat"|"lreverse"|"memory"|"namespace"|"open"|
        "package"|"pid"|"pkg_mkIndex"|"pkg::create"|"pwd"|"rename"|"seek"|"socket"|"source"|
        "tcl_findLibrary"|"tell"|"time"|"trace"|"unknown"|"update" => {
            results.push(Warn(ctx, "Use of unsupported command:", tokens[0].val));
            iter::repeat(Code::Normal).take(tokens.len()-1).collect()
        },
        "uplevel"|"history" => {
            results.push(Danger(ctx, "Use of unsafe command:", tokens[0].val));
            iter::repeat(Code::Normal).take(tokens.len()-1).collect()
        },
        // deprecated iRule commands
        "accumulate"|"client_addr"|"client_port"|"decode_uri"|"findclass"|
        "http_cookie"|"http_header"|"http_host"|"http_method"|"http_uri"|"http_version"|
        "imid"|"ip_addr"|"ip_protocol"|"ip_tos"|"ip_ttl"|"link_qos"|"local_addr"|"local_port"|
        "matchclass"|"redirect"|"remote_addr"|"remote_port"|"server_addr"|"server_port"|"urlcatblindquery"|"urlcatquery"|"use"|
        "vlan_id" => {
            results.push(Warn(ctx, "Use of deprecated command:", tokens[0].val));
            iter::repeat(Code::Normal).take(tokens.len()-1).collect()
        },
        "after" => match tokens[1].val {
            "cancel"|"info" => {
                // after cancel|info 123
                // after cancel|info {123 987}
                // after cancel|info [list 12 34 56]
                if ! (tokens[1].val == "cancel" && tokens[2].val == "-current") {
                    vec![Code::Literal, Code::Normal]
                } else {
                    // after cancel -current
                    vec![Code::Literal, Code::Literal]
                }
            },
            _ => match tokens.len() {
                // after <ms>
                2 => vec![Code::Normal],
                // after <ms> < script >
                3 => vec![Code::Normal, Code::Block],
                // after <ms> [-periodic] < script >
                _ => vec![Code::Normal, Code::Literal, Code::Block],
            },
        },
        // TODO: switch ?options? string pattern body ?pattern body …?
        //               options: -exact -glob -regexp --
        // switch -exact -glob -regexp --
        "switch" => {
            let param_types = vec![Code::Literal];
            //let tokens_start = 3;
            if tokens.len() == 3 {
                results.push(Danger(ctx, "missing options terminator", "--"));
            }
            results.push(Warn(ctx, "Cannot scan switch, not implemented (TODO, known-issue).", ""));
            param_types
        },
        // class search [-index -name -value -element -all --]
        // class match [-index -name -value -element -all --]
        // class nextelement [-index -name -value --] <class> <search_id>
        // class element [-name -value --] <index> <class>
        "class" => {
            let tokens_total_len = match tokens[1].val {
                "search"|"match" => tokens.len()-3,
                _ => tokens.len()-2,
            };
            let mut options_terminated = false;
            let mut i = 2;
            while i < tokens_total_len {
                if tokens[i].val == "--" {
                    options_terminated = true; break;
                }
                i += 1;
            }
            if ! options_terminated {
                results.push(Danger(ctx, "missing options terminator `--` permits argument injection", tokens[i].val));
            }
            iter::repeat(Code::Normal).take(tokens.len()-1).collect()
        },
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
                results.push(Danger(ctx, "missing options terminator `--` permits argument injection", tokens[pos].val));
            }
            iter::repeat(Code::Normal).take(tokens.len()-1).collect()
        },
        //regexp -about -expanded -indices -line -linestop -lineanchor -nocase -all -inline -start <index> --
        //regsub -all -expanded -line -linestop -lineanchor -nocase -start <index> --
        "regexp"|"regsub" => {
            let mut options_terminated = false;
            let mut i = 1;
            while i < tokens.len() {
                match tokens[i].val {
                    "-about"|"-all"|"-expanded"|"-indices"|
                    "-inline"|"-line"|"-lineanchor"|"-linestop"|
                    "-nocase" => { i += 1; },
                    "-start" => { i += 2; },
                    "--" => { options_terminated = true; break; },
                    _ => {break;},
                };
            };
            if ! options_terminated {
                results.push(Danger(ctx, "missing options terminator `--` permits argument injection", tokens[i].val));
            }
            iter::repeat(Code::Normal).take(tokens.len()-1).collect()
        },
        // default
        _ => iter::repeat(Code::Normal).take(tokens.len()-1).collect(),
    };
    if param_types.len() != tokens.len() - 1 {
        results.push(Warn(ctx, "badly formed command", tokens[0].val));
        return results;
    }
    for (param_type, param) in param_types.iter().zip(tokens[1..].iter()) {
        let check_results: Vec<CheckResult<'a>> = match *param_type {
            Code::Block => check_block(ctx, param),
            Code::Expr => check_expr(ctx, param),
            Code::Literal => check_literal(ctx, param),
            Code::Normal => vec![],
        };
        results.extend(check_results.into_iter());
    }
    return results;
}

/// Scans a block (i.e. should be quoted) for danger
fn check_block<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>) -> Vec<CheckResult<'a>> {
    let block_str = token.val;
    if !(block_str.starts_with("{") && block_str.ends_with("}")) {
        return vec!(match is_safe_val(token) {
            true => Warn(ctx, "Unquoted block", block_str),
            false => Danger(ctx, "Dangerous unquoted block", block_str),
        });
    }
    // Block isn't inherently dangerous, let's check functions inside the block
    let script_str = &block_str[1..block_str.len()-1];
    return scan_script(script_str);
}

/// Scans an expr (i.e. should be quoted) for danger
fn check_expr<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>) -> Vec<CheckResult<'a>> {
    let mut results = vec![];
    let expr_str = token.val;
    if !(expr_str.starts_with("{") && expr_str.ends_with("}")) {
        results.push(match is_safe_val(token) {
            true => Warn(ctx, "Unquoted expr", expr_str),
            false => Danger(ctx, "Dangerous unquoted expr", expr_str),
        });
        return results;
    };
    // Technically this is the 'scan_expr' function
    // Expr isn't inherently dangerous, let's check functions inside the expr
    assert!(token.val.starts_with("{") && token.val.ends_with("}"));
    let expr = &token.val[1..token.val.len()-1];
    let (parse, remaining) = rstcl::parse_expr(expr);
    assert!(parse.tokens.len() == 1 && remaining == "");
    for tok in parse.tokens[0].iter().filter(|tok| tok.ttype == TokenType::Command) {
        results.extend(scan_command(tok.val).into_iter());
    }
    return results;
}

/// Scans a TokenType::Command token (contained in '[]') for danger
pub fn scan_command<'a>(string: &'a str) -> Vec<CheckResult<'a>> {
    assert!(string.starts_with("[") && string.ends_with("]"));
    let script = &string[1..string.len()-1];
    return scan_script(script);
}

/// Scans a sequence of commands for danger
pub fn scan_script<'a>(string: &'a str) -> Vec<CheckResult<'a>> {
    let mut all_results: Vec<CheckResult<'a>> = vec![];
    for parse in rstcl::parse_script(string) {
        let results = check_command(&parse.command.unwrap(), &parse.tokens);
        all_results.extend(results.into_iter());
    }
    return all_results;
}
