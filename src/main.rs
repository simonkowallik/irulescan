use irulescan::rstcl;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use serde_json::Value;
use json_diff_ng::compare_serde_values;

use clap::{Parser, Subcommand};
use walkdir::WalkDir;

use irulescan::scan_and_format_results;

mod apiserver;
mod mcpserver;

static IRULE_FILE_EXTENSIONS: [&str; 3] = [".irule", ".irul", ".tcl"];

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
// --- Main Function ---

#[derive(Parser)]
#[command(name = "irulescan")]
#[command(version = "3.0.0")]
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
    /// Scan all iRules in a directory (recursively) or the specified file or - for stdin.
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

    /// Run MCP server (HTTP stream transport)
    Mcpserver {
        /// listening addr, eg. 127.0.0.1:8888 or 0.0.0.0:80
        #[arg(long, default_value_t = SocketAddr::from(([127, 0, 0, 1], 8000)))]
        listen: SocketAddr,

        /// Include iRule security good practices in scan results to provide additional context to the LLM.
        #[arg(long, default_value_t = false)]
        include_good_practices: bool,
    },
    /// Run HTTP API server (OpenAPI v3)
    Apiserver {
        /// listening addr, eg. 127.0.0.1:8888 or 0.0.0.0:80
        #[arg(long, default_value_t = SocketAddr::from(([127, 0, 0, 1], 8000)))]
        listen: SocketAddr,
    },
}

// --- Main Function ---
#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Check { no_warn, exclude_empty_findings, reference, dirpath } => {
            let mut script_ins: Vec<(String, String)> = Vec::new();
            
            let mut is_stdin = false;

            if dirpath.to_str().unwrap() == "-" {
                // Read from STDIN when dirpath is "-"
                let stdin_content = read_stdin();
                is_stdin = true;
                script_ins.push(("STDIN".to_string(), stdin_content));
            } else if dirpath.is_file() {
                // If dirpath is a file, read the file regardless of the file extension
                script_ins.push((
                    dirpath.to_str().unwrap().trim_start_matches("./").to_string(),
                    read_file(&dirpath),
                ));
            } else if dirpath.is_dir() {
                // If dirpath is a directory, read all files that match IRULE_FILE_EXTENSIONS
                for entry in WalkDir::new(&dirpath)
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
            } else {
                eprintln!("ERROR: Invalid filepath: {:?}, not a file or directory", dirpath);
                std::process::exit(1);
            }

            let mut preprocessed_scripts: Vec<(String, String)> = Vec::new();
            for (_path, script_in) in script_ins.iter() {
                let script = irulescan::preprocess_script(&script_in);
                preprocessed_scripts.push((_path.to_string(), script));
            }

            // Call the new combined function
            let mut scan_results = scan_and_format_results(&preprocessed_scripts, no_warn, exclude_empty_findings);

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
            // --- End of Check command logic ---\\
        }
        Commands::Checkref { no_warn, filepath } => {
            // --- Existing Checkref command logic --- \
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

            let scan_results = scan_and_format_results(&preprocessed_scripts, no_warn, false);

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
            // --- Existing Parsestr command logic --- \
            let take_stdin = script_str == "-";
            let script_in = match take_stdin {
                true => read_stdin(),
                false => script_str,
            };
            let script = &irulescan::preprocess_script(&script_in);
            println!("{:?}", rstcl::parse_script(script));
        }
        Commands::Mcpserver { listen, include_good_practices } => {
            mcpserver::run_mcpserver(listen, include_good_practices).await;
        }
        Commands::Apiserver { listen } => {
            apiserver::run_apiserver(listen).await;
        }
    }
}
