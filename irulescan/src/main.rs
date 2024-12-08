use irulescan::rstcl;
use irulescan::CheckResult;
use serde_json::Value;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use serde_json::json;
use json_diff_ng::compare_serde_values;

use clap::{Parser, Subcommand};

static IRULE_FILE_EXTENSIONS: [&str; 3] = [".irule", ".irul", ".tcl"];

fn results_to_json(complex_results: Vec<(String, Vec<CheckResult>)>, exclude_empty_findings: bool) -> serde_json::Value {
    let mut result_list = Vec::new();

    for (path, check_results) in complex_results.iter() {
        let mut warning = Vec::new();
        let mut dangerous = Vec::new();

        if check_results.len() > 0 {
            for check_result in check_results.iter() {
                match check_result {
                    &CheckResult::Warn(ref ctx, ref msg, ref line) => {
                        let _ = warning.push(format!(
                            "{} at `{}` in `{}`",
                            msg,
                            line,
                            ctx.replace("\n", "")
                        ));
                    }
                    &CheckResult::Danger(ref ctx, ref msg, ref line) => {
                        let _ = dangerous.push(format!(
                            "{} at `{}` in `{}`",
                            msg,
                            line,
                            ctx.replace("\n", "")
                        ));
                    }
                }
            }
        };
        if exclude_empty_findings && warning.len() == 0 && dangerous.len() == 0 {
            continue;
        }
        let json_entries = json!({
            "filepath": path,
            "warning": warning,
            "dangerous": dangerous
        });
        let _ = result_list.push(json_entries);
    }

    return serde_json::json!(result_list);
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
    if let Err(err) = io::stdin().read_to_string(&mut stdin_content) {
        panic!("ERROR: Couldn't read STDIN: {}", format!("{}", &err));
    }
    stdin_content
}

#[derive(Parser)]
#[command(name = "irulescan")]
#[command(version = "2.0.0")]
#[command(author = "Simon Kowallik <github@simonkowallik.com>")]
#[command(about = "irulescan - security analyzer for iRules")]
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
    /// Scan all iRules in a directory (recursively) or the specified file.
    #[command(arg_required_else_help = true, long_about = "Scan all iRules in a directory (recursively) or the specified file. Processes iRules with non-case sensitive file extensions: .irule, .irul, .tcl and outputs JSON array of objects (results).")]
    Check {
        /// Suppress findings of type "warning"
        #[arg(long)]
        no_warn: bool,

        /// Exclude entries for iRules with empty results (neither "warning" nor "dangerous" findings present)
        #[arg(long)]
        exclude_empty_findings: bool,

        /// Reference file (eg. from previous scan) to compare scan results to.
        /// Differences are reported and the program will exit with a non-zero exit code.
        #[arg(short, long, value_name = "REFERENCE_FILEPATH")]
        reference: Option<PathBuf>,

        /// Scan iRules in this directory (recursively) or the specified iRule file, use - to scan STDIN.
        #[arg(required = true, value_name = "FILEPATH")]
        dirpath: PathBuf,
    },
    /// Scan all iRules in reference file (JSON) and compare to reference.
    #[command(arg_required_else_help = true)]
    Checkref {
        /// Suppress findings of type "warning"
        #[arg(long)]
        no_warn: bool,

        /// Input file or - for stdin
        #[arg(required = true, value_name = "REFERENCE-FILEPATH")]
        filepath: PathBuf,
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
        Commands::Check { no_warn, exclude_empty_findings, reference, dirpath } => {
            let mut script_ins: Vec<(String, String)> = Vec::new();
            
            let mut is_stdin = false;

            if dirpath.to_str().unwrap() == "-" {
                // Read from STDIN when dirpath is "-"
                let stdin_content = read_stdin();
                is_stdin = true;
                script_ins.push(("STDIN".to_string(), stdin_content));
            } else {
                // Normal directory/file handling
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

            let mut scan_results = results_to_json(complex_results, exclude_empty_findings);

            // for STDIN only output the result object without the filepath
            if is_stdin {
                scan_results = scan_results.as_array().unwrap()[0].clone();
                scan_results.as_object_mut().unwrap().remove("filepath");
            }

            if reference.is_some() {
                let reference_results_str = read_file(&reference.unwrap());
                let reference_results = match serde_json::from_str(&reference_results_str) {
                    Ok(results) => results,
                    Err(err) => {
                        eprintln!("Failed to parse JSON of reference file: {}", err);
                        std::process::exit(1);
                    }
                };

                let diffs = compare_serde_values(&reference_results, &scan_results, true, &[]).unwrap();

                if diffs.is_empty() {
                    println!("OK");
                } else {
                    println!("Failed reference check!");
                    for (d_type, d_path) in diffs.all_diffs() {
                        let mut _message = format!("{d_type}: {d_path}");
                        let mut _message = _message.replace("Extra on left:", "Extra in reference:");
                        let mut _message = _message.replace("Extra on right:", "Extra in scan_results:");
                        let mut _message = _message.replace("Mismatched:", "Mismatch (reference != scan):");
                        println!("{}", _message);
                    }
                    // exit with error code on differences
                    std::process::exit(1);
                }
            } else {
                println!("{}", scan_results.to_string());
            }
        }
        Commands::Checkref { no_warn, filepath } => {
            let take_stdin = filepath.to_str().unwrap() == "-";

            let reference_in = match take_stdin {
                true => read_stdin(),
                false => read_file(&filepath),
            };
            let reference_results: Value = match serde_json::from_str(&reference_in) {
                Ok(results) => results,
                Err(err) => {
                    eprintln!("Failed to parse JSON of reference file: {}", err);
                    std::process::exit(1);
                }
            };

            let mut script_ins: Vec<(String, String)> = Vec::new();
            // example: reference_results = [{"filepath": "file1"}, {"filepath": "file2"}, {"filepath": "file3"}]
            for entry in reference_results.as_array().unwrap().iter() {
                let _path = entry.get("filepath").unwrap().as_str().unwrap();
                let _path = Path::new(_path);
                if _path.is_file() {
                    script_ins.push((
                        _path.to_str().unwrap().to_string(),
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

            let scan_results = results_to_json(complex_results, false);

            let diffs = compare_serde_values(&reference_results, &scan_results, true, &[]).unwrap();

            if diffs.is_empty() {
                println!("OK");
            } else {
                println!("Failed reference check!");
                for (d_type, d_path) in diffs.all_diffs() {
                    let mut _message = format!("{d_type}: {d_path}");
                    let mut _message = _message.replace("Extra on left:", "Extra in reference:");
                    let mut _message = _message.replace("Extra on right:", "Extra in scan_results:");
                    let mut _message = _message.replace("Mismatched:", "Mismatch (reference != scan):");
                    println!("{}", _message);
                }
                // exit with error code on differences
                std::process::exit(1);
            }
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
