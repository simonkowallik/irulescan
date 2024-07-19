use irulescan::rstcl;
use irulescan::CheckResult;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use json::object;

static IRULE_FILE_EXTENSIONS: [&str; 3] = [".irule", ".irul", ".tcl"];

fn complex_results_to_json(complex_results: Vec<(String, Vec<CheckResult>)>) -> json::JsonValue {
    let mut jsonresult_list = json::JsonValue::new_array();

    for (path, check_results) in complex_results.iter() {
        let mut jsonresult = json::JsonValue::new_object();
        jsonresult["filepath"] = path.clone().into();
        jsonresult["warning"] = json::JsonValue::new_array();
        jsonresult["dangerous"] = json::JsonValue::new_array();

        if check_results.len() > 0 {
            for check_result in check_results.iter() {
                match check_result {
                    &CheckResult::Warn(ref ctx, ref msg, ref line) => {
                        let _ = jsonresult["warning"].push(format!(
                            "{} at `{}` in `{}`",
                            msg,
                            line,
                            ctx.replace("\n", "")
                        ));
                    }
                    &CheckResult::Danger(ref ctx, ref msg, ref line) => {
                        let _ = jsonresult["dangerous"].push(format!(
                            "{} at `{}` in `{}`",
                            msg,
                            line,
                            ctx.replace("\n", "")
                        ));
                    }
                }
            }
        };

        let _ = jsonresult_list.push(jsonresult);
    }

    return jsonresult_list;
}

fn results_to_json(results: Vec<CheckResult>) -> json::JsonValue {
    let mut jsondata = object! {
        warning: [],
        dangerous: []
    };
    if results.len() > 0 {
        for check_result in results.iter() {
            match check_result {
                &CheckResult::Warn(ref ctx, ref msg, ref line) => {
                    let _ = jsondata["warning"].push(format!(
                        "{} at `{}` in `{}`",
                        msg,
                        line,
                        ctx.replace("\n", "")
                    ));
                }
                &CheckResult::Danger(ref ctx, ref msg, ref line) => {
                    let _ = jsondata["dangerous"].push(format!(
                        "{} at `{}` in `{}`",
                        msg,
                        line,
                        ctx.replace("\n", "")
                    ));
                }
            }
        }
    };
    return jsondata;
}

fn read_file(path: &Path) -> String {
    let path_display = path.display();
    let mut file = match fs::File::open(&path) {
        Err(err) => panic!(
            "ERROR: Couldn't open {}: {}",
            path_display,
            format!("{}", &err)
        ),
        Ok(file) => file,
    };
    let mut file_content = String::new();
    match file.read_to_string(&mut file_content) {
        Err(err) => panic!(
            "ERROR: Couldn't read {}: {}",
            path_display,
            format!("{}", &err)
        ),
        Ok(_) => file_content,
    }
}

fn read_stdin() -> String {
    let mut stdin_content = String::new();
    match io::stdin().read_to_string(&mut stdin_content) {
        Err(err) => panic!("ERROR: Couldn't read stdin: {}", format!("{}", &err)),
        Ok(_) => stdin_content,
    }
}

#[derive(Parser)]
#[command(name = "irulescan")]
#[command(version = "2.0.0")]
#[command(author = "Simon Kowallik <github@simonkowallik.com>")]
#[command(about = "irulescan - static security analyzer for iRules")]
#[command(
    long_about = "irulescan is a tool to scan iRules for unexpected/unsafe expressions that may have undesirable effects like double substitution.\nhome: https://github.com/simonkowallik/irulescan"
)]
#[command(propagate_version = true)]

struct Cli {
    /// Subcommands
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check iRule (either a file or stdin)
    #[command(arg_required_else_help = true)]
    Check {
        /// suppress findings of type "warning"
        #[arg(short, long)]
        no_warn: bool,

        /// produce JSON output
        #[arg(long)]
        json: bool,

        /// Input file or - for stdin
        #[arg(required = true)]
        filepath: PathBuf,
    },
    /// Check all iRules in a directory (recursively)
    /// Output is a JSON object, supported non-case sensitive file extensions are .irule, .irul, .tcl
    #[command(arg_required_else_help = true)]
    Checkdir {
        /// suppress findings of type "warning"
        #[arg(short, long)]
        no_warn: bool,

        /// Scan iRules in this directory (recursively)
        #[arg(required = true)]
        dirpath: PathBuf,
    },
    /// Parse given string or stdin
    #[command(arg_required_else_help = true)]
    Parsestr {
        /// String, - for stdin
        #[arg(required = true)]
        script_str: String,
    },
}

fn main() {
    let args = Cli::parse();
    let _command = args.command;

    match _command {
        Commands::Check {
            no_warn,
            json,
            filepath,
        } => {
            let take_stdin = filepath.to_str().unwrap() == "-";

            let script_in = match take_stdin {
                true => read_stdin(),
                false => read_file(&filepath),
            };
            let script = &irulescan::preprocess_script(&script_in);
            let mut results = irulescan::scan_script(script);

            // filter out warnings if --no-warn flag is set
            if no_warn {
                results = results
                    .into_iter()
                    .filter(|r| match r {
                        &CheckResult::Warn(_, _, _) => false,
                        _ => true,
                    })
                    .collect();
            }

            // print results as json if --json flag is set
            if json {
                println!("{}", results_to_json(results).dump());
            } else {
                if results.len() > 0 {
                    for check_result in results.iter() {
                        // HACK: restore original rand() by removing artificial parameter
                        println!(
                            "{}",
                            format!("{}", check_result).replace("rand($IRULESCAN)", "rand()")
                        );
                    }
                    println!("");
                };
            };
        }
        Commands::Checkdir { no_warn, dirpath } => {
            let mut script_ins: Vec<(String, String)> = Vec::new();
            for entry in walkdir::WalkDir::new(&dirpath)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let _path = entry.path();
                if IRULE_FILE_EXTENSIONS
                    .iter()
                    .any(|&x| _path.to_str().unwrap().to_lowercase().ends_with(x))
                    && _path.is_file()
                {
                    script_ins.push((
                        _path.to_str().unwrap().trim_start_matches("./").to_string(),
                        read_file(&_path),
                    ));
                }
            }

            let mut preprocessed_scripts: Vec<(String, String)> = Vec::new();
            for (_path, script_in) in script_ins.iter() {
                let script = irulescan::preprocess_script(&script_in);
                preprocessed_scripts.push((_path.to_string(), script));
            }

            let mut complex_results: Vec<(String, Vec<CheckResult>)> = Vec::new();
            for (_path, script) in preprocessed_scripts.iter() {
                let mut res = irulescan::scan_script(&script);

                // filter out warnings if --no-warn flag is set
                if no_warn {
                    res = res
                        .into_iter()
                        .filter(|r| match r {
                            &CheckResult::Warn(_, _, _) => false,
                            _ => true,
                        })
                        .collect();
                }

                complex_results.push((_path.to_string(), res));
            }

            println!("{}", complex_results_to_json(complex_results).dump());
        }
        Commands::Parsestr { script_str } => {
            let take_stdin = script_str == "-";
            let script_in = match take_stdin {
                true => read_stdin(),
                false => script_str,
            };
            let script = &irulescan::preprocess_script(&script_in);
            println!("{:?}", rstcl::parse_script(script));
        }
    }
}
