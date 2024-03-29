#![feature(plugin)]

extern crate rustc_serialize;
extern crate docopt;
extern crate irulescan;

use std::fs;
use std::io::prelude::*;
use std::io;
use std::path::Path;
use docopt::Docopt;
use irulescan::rstcl;
use irulescan::CheckResult;

const USAGE: &'static str = "
Usage: irulescan check [--no-warn] ( - | <path> )
       irulescan parsestr ( - | <script-str> )
Additional Information:
    home: https://github.com/simonkowallik/irulescan
    version: 1.1.1
";

pub fn main() {
    let args = Docopt::new(USAGE)
                        .and_then(|dopt| dopt.parse())
                        .unwrap_or_else(|e| e.exit());

    let take_stdin = args.get_bool("-");
    let cmd_check = args.get_bool("check");
    let cmd_parsestr = args.get_bool("parsestr");
    let flag_no_warn = args.get_bool("--no-warn");

    let arg_path = args.get_str("<path>");
    let arg_script_str = args.get_str("<script-str>");

    let script_in = match (cmd_check, cmd_parsestr, take_stdin) {
        (true, false, false) => {
            let path = Path::new(&arg_path);
            let path_display = path.display();
            let mut file = match fs::File::open(&path) {
                Err(err) => panic!("ERROR: Couldn't open {}: {}",
                                   path_display, format!("{}", &err)),
                Ok(file) => file,
            };
            let mut file_content = String::new();
            match file.read_to_string(&mut file_content) {
                Err(err) => panic!("ERROR: Couldn't read {}: {}",
                                   path_display, format!("{}", &err)),
                Ok(_) => file_content,
            }
        },
        (true, false, true) |
        (false, true, true) => {
            let mut stdin_content = String::new();
            match io::stdin().read_to_string(&mut stdin_content) {
                Err(err) => panic!("ERROR: Couldn't read stdin: {}",
                                    format!("{}", &err)),
                Ok(_) => stdin_content,
            }
        },
        (false, true, false) => arg_script_str.to_owned(),
        _ => panic!("Internal error: could not load script"),
    };
    let script = &irulescan::preprocess_script(&script_in);
    match (cmd_check, cmd_parsestr) {
        (true, false) => {
            let mut results = irulescan::scan_script(script);
            if flag_no_warn {
                results = results.into_iter().filter(|r|
                    match r { &CheckResult::Warn(_, _, _) => false,  _ => true }
                ).collect();
            }
            if results.len() > 0 {
                for check_result in results.iter() {
                    // HACK: restore original rand() by removing artificial parameter
                    println!("{}", format!("{}",check_result).replace("rand($IRULESCAN)", "rand()"));
                }
                println!("");
            };
        },
        (false, true) =>
            println!("{:?}", rstcl::parse_script(script)),
        _ =>
            panic!("Internal error: invalid operation"),
    }
}
