use irulescan::rstcl;
use serde_json::Value;
use std::fs;
use std::io::{self, Write};
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use serde_json::json;
use json_diff_ng::compare_serde_values;

use clap::{Parser, Subcommand};
use walkdir::WalkDir;

// API Server imports
use axum::{
    routing::post,
    http::StatusCode,
    response::{IntoResponse, Json},
    extract::{DefaultBodyLimit, Query},
    Router,
};
use axum_extra::extract::Multipart;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tempfile::NamedTempFile; // For handling file uploads

// OpenAPI / Swagger UI imports
use utoipa::{OpenApi, ToSchema, IntoParams};
use utoipa_swagger_ui::SwaggerUi;

static IRULE_FILE_EXTENSIONS: [&str; 3] = [".irule", ".irul", ".tcl"];

// --- CLI Helper Functions ---

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

fn scan_and_format_results(
    preprocessed_scripts: &Vec<(String, String)>,
    no_warn: bool,
    exclude_empty_findings: bool,
) -> serde_json::Value {
    let mut result_list = Vec::new();

    for (path, script) in preprocessed_scripts.iter() {
        let mut res = irulescan::scan_script(&script);

        // filter out warnings if --no-warn flag is set
        if no_warn {
            res = res
                .into_iter()
                .filter(|r| match r {
                    &irulescan::CheckResult::Warn(_, _, _) => false,
                    _ => true,
                })
                .collect();
        }

        // JSON formatting logic from results_to_json
        let mut warning = Vec::new();
        let mut dangerous = Vec::new();

        if res.len() > 0 {
            for check_result in res.iter() {
                match check_result {
                    &irulescan::CheckResult::Warn(ref ctx, ref msg, ref line) => {
                        let _ = warning.push(format!(
                            "{} at `{}` in `{}`",
                            msg,
                            line,
                            ctx.replace("\n", "")
                        ));
                    }
                    &irulescan::CheckResult::Danger(ref ctx, ref msg, ref line) => {
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

    /// Start the API server
    #[command(arg_required_else_help = false)]
    Apiserver {
        /// IP address and port to listen on (e.g., 127.0.0.1:8000)
        #[arg(long, value_name = "IP:PORT", default_value = "127.0.0.1:8000")]
        listen: SocketAddr,
    },
}

// --- API Parameter & Schema Structs ---

#[derive(Deserialize, ToSchema, IntoParams)]
struct ScanParams {
    #[serde(default)] // Make it optional in query
    no_warn: Option<bool>,
    #[serde(default)] // Make it optional in query
    exclude_empty_findings: Option<bool>,
}

#[derive(Deserialize, ToSchema, IntoParams)]
struct ScanFilesParams {
    #[serde(default)] // Make it optional in query
    no_warn: Option<bool>,
    #[serde(default)] // Make it optional in query
    exclude_empty_findings: Option<bool>,
}

// Define a specific response struct for scan_handler
#[derive(Serialize, ToSchema)]
struct ScanBodyResponseEntry {
    warning: Vec<String>,
    dangerous: Vec<String>,
}

#[derive(Serialize, ToSchema)] // Keep this for scan_files_handler response
struct ScanFilesResponseEntry {
    filepath: String,
    warning: Vec<String>, // Use Vec<String> instead of Value for better schema
    dangerous: Vec<String>, // Use Vec<String> instead of Value for better schema
}

// --- OpenAPI Documentation Struct ---
#[derive(OpenApi)]
#[openapi(
    paths(
        scan_handler,
        scan_files_handler,
    ),
    components(
        schemas(ScanParams, ScanFilesParams, ScanBodyResponseEntry, ScanFilesResponseEntry)
    ),
    tags(
        (name = "irulescan", description = "iRule Scanning API")
    )
)]
struct ApiDoc;

// --- API Handlers ---

#[utoipa::path(
    post,
    path = "/scan",
    tag = "irulescan",
    params(
        ScanParams
    ),
    request_body = String,
    responses(
        (status = 200, description = "Scan successful", body = [ScanBodyResponseEntry])
    )
)]
async fn scan_handler(
    Query(params): Query<ScanParams>, // Extract params from query
    body: String, // Extract request body as String
) -> impl IntoResponse {
    let script_in = body;
    let no_warn = params.no_warn.unwrap_or(false);
    let exclude_empty_findings = params.exclude_empty_findings.unwrap_or(false);

    let script = irulescan::preprocess_script(&script_in);
    let preprocessed_scripts = vec![("request_body".to_string(), script)];

    let scan_results_json = scan_and_format_results(&preprocessed_scripts, no_warn, exclude_empty_findings);

    let original_results: Vec<serde_json::Value> = scan_results_json.as_array()
        .cloned()
        .unwrap_or_else(Vec::new);

    // Convert to ScanBodyResponseEntry
    let mut response_entries: Vec<ScanBodyResponseEntry> = Vec::new();
    for result_obj in original_results {
        let warning: Vec<String> = serde_json::from_value(result_obj.get("warning").cloned().unwrap_or_else(|| json!([]))).unwrap_or_default();
        let dangerous: Vec<String> = serde_json::from_value(result_obj.get("dangerous").cloned().unwrap_or_else(|| json!([]))).unwrap_or_default();

        response_entries.push(ScanBodyResponseEntry {
            warning,
            dangerous,
        });
    }

    (StatusCode::OK, Json(response_entries))
}

#[utoipa::path(
    post,
    path = "/scanfiles",
    tag = "irulescan",
    params(
        ScanFilesParams
    ),
    request_body(content_type = "multipart/form-data", description = "iRule files to scan"),
    responses(
        (status = 200, description = "Scan successful", body = [ScanFilesResponseEntry])
    )
)]
async fn scan_files_handler(
    Query(params): Query<ScanFilesParams>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let no_warn = params.no_warn.unwrap_or(false);
    let exclude_empty_findings = params.exclude_empty_findings.unwrap_or(false);
    let mut response_files: Vec<ScanFilesResponseEntry> = Vec::new();

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.file_name().unwrap_or_else(|| field.name().unwrap_or("unknown_file")).to_string();
        let data = field.bytes().await.unwrap();

        let script_in = match String::from_utf8(data.to_vec()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Skipping file '{}': Invalid UTF-8 sequence: {}", name, e);
                continue;
            }
        };

        if script_in.is_empty() {
            tracing::warn!("Skipping empty file '{}'", name);
            continue;
        }
        let script = irulescan::preprocess_script(&script_in);
        let preprocessed_scripts = vec![(name.clone(), script)];

        let scan_results_json = scan_and_format_results(&preprocessed_scripts, no_warn, exclude_empty_findings);

        if let Some(file_results_obj) = scan_results_json.as_array().and_then(|arr| arr.get(0)).cloned() {
            // Convert Value to Vec<String>
            let warning: Vec<String> = serde_json::from_value(file_results_obj.get("warning").cloned().unwrap_or_else(|| json!([]))).unwrap_or_default();
            let dangerous: Vec<String> = serde_json::from_value(file_results_obj.get("dangerous").cloned().unwrap_or_else(|| json!([]))).unwrap_or_default();

            response_files.push(ScanFilesResponseEntry {
                filepath: name,
                warning,
                dangerous,
            });
        }
    }

    (StatusCode::OK, Json(response_files))
}

// --- Main Function ---
#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Check { no_warn, exclude_empty_findings, reference, dirpath } => {
            // --- Existing Check command logic --- \
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
            // --- End of Check command logic ---\
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
        Commands::Apiserver { listen } => {
            // --- New Apiserver command logic ---
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(
                    std::env::var("IRULESCAN_LOG").unwrap_or_else(|_| "info".into()),
                ))
                .with(tracing_subscriber::fmt::layer())
                .init();

            // Build the Axum app with API routes and Swagger UI
            let app = Router::new()
                // Add Swagger UI endpoint first
                .merge(SwaggerUi::new("/").url("/openapi.json", ApiDoc::openapi()))
                // API routes
                .route("/scan", post(scan_handler))
                .route("/scan/", post(scan_handler)) // Keep trailing slash variant?
                .route("/scanfiles", post(scan_files_handler))
                .route("/scanfiles/", post(scan_files_handler)) // Keep trailing slash variant?
                // Layers
                .layer(TraceLayer::new_for_http())
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10MB limit

            tracing::info!("irulescan API listening on {}", listen);
            tracing::info!("Swagger UI available at /");
            tracing::info!("OpenAPI 3.1 spec available at /openapi.json");
            let listener = TcpListener::bind(listen).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        }
    }
}
