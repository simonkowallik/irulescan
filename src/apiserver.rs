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
use std::panic::{catch_unwind, AssertUnwindSafe};
use tokio::net::TcpListener;
use tower_http::trace::{TraceLayer, DefaultMakeSpan};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use utoipa::{OpenApi, ToSchema, IntoParams};
use utoipa_swagger_ui::SwaggerUi;
use serde_json::json;

use irulescan::scan_and_format_results;

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub(crate) struct FindingDetail {
    message: String,
    issue_location: String,
    context: String,
    line: usize,
}

#[derive(Deserialize, ToSchema, IntoParams)]
pub(crate) struct ScanParams {
    #[serde(default)]
    no_warn: Option<bool>,
    #[serde(default)]
    exclude_empty_findings: Option<bool>,
}

#[derive(Deserialize, ToSchema, IntoParams)]
pub(crate) struct ScanFilesParams {
    #[serde(default)]
    no_warn: Option<bool>,
    #[serde(default)]
    exclude_empty_findings: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ScanBodyResponseEntry {
    warning: Vec<FindingDetail>,
    dangerous: Vec<FindingDetail>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ScanFilesResponseEntry {
    filepath: String,
    warning: Vec<FindingDetail>,
    dangerous: Vec<FindingDetail>,
}

#[derive(OpenApi)]
#[openapi(
    info(
        description = "irulescan - security analyzer for iRules",
        title = "irulescan API",
        version = "3.0.0",
        ),
    external_docs(
        description = "irulescan documentation",
        url = "https://simonkowallik.github.io/irulescan/"
    ),
    paths(
        scan_handler,
        scan_files_handler,
    ),
    components(
        schemas(ScanParams, ScanFilesParams, ScanBodyResponseEntry, ScanFilesResponseEntry, FindingDetail)
    ),
    tags(
        (name = "irulescan", description = "irulescan API - security analyzer for iRules")
    )
)]
struct ApiDoc;

#[utoipa::path(
    post,
    path = "/scan",
    tag = "irulescan",
    description = "Scan POST data for iRule security issues.",
    params(
        ScanParams
    ),
    request_body(
        content = String,
        description = "iRule code to scan",
        example = r#"when HTTP_REQUEST {
    set one 1
    expr 1 + $one
    switch [HTTP::header value "X-Header"] {
        "*value1*" { log local0. "`*value1*`, raw header content: [HTTP::header value "X-Header"]" }
        default { log local0. "Default value" }
    }
}"#,
    ),
    responses(
        (status = 200, description = "Returns the irulescan result.", body = ScanBodyResponseEntry),
        (status = 500, description = "Internal server error during scan.", body = String)
    ),
)]
async fn scan_handler(
    Query(params): Query<ScanParams>,
    body: String,
) -> impl IntoResponse {
    let script_in = body;
    let no_warn = params.no_warn.unwrap_or(false);
    let exclude_empty_findings = params.exclude_empty_findings.unwrap_or(false);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let script = irulescan::preprocess_script(&script_in);
        let preprocessed_scripts = vec![("request_body".to_string(), script)];
        scan_and_format_results(&preprocessed_scripts, no_warn, exclude_empty_findings)
    }));

    match result {
        Ok(scan_results) => {
            // Extract results for the single "request_body" entry
            let result_obj = scan_results
                .as_array()
                .and_then(|arr| arr.get(0))
                .cloned()
                .unwrap_or_else(|| json!({"warning": [], "dangerous": []})); // Default if empty

            // Safely extract warning and dangerous fields
            let warning: Vec<FindingDetail> = serde_json::from_value(
                result_obj.get("warning").cloned().unwrap_or_else(|| json!([]))
            ).unwrap_or_default();

            let dangerous: Vec<FindingDetail> = serde_json::from_value(
                result_obj.get("dangerous").cloned().unwrap_or_else(|| json!([]))
            ).unwrap_or_default();

            (StatusCode::OK, Json(ScanBodyResponseEntry { warning, dangerous })).into_response()
        }
        Err(panic_payload) => {
            let error_message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                format!("Internal server error during scan: {}", s)
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                format!("Internal server error during scan: {}", s)
            } else {
                "Internal server error during scan: Unknown panic reason".to_string()
            };
            tracing::error!("Panic: {}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message).into_response()
        }
    }
}


#[utoipa::path(
    post,
    path = "/scanfiles",
    tag = "irulescan",
    description = "Scan iRule files for security issues.",
    params(
        ScanFilesParams
    ),
    request_body(
        content_type = "multipart/form-data",
        description = "iRule files to scan"
    ),
    responses(
        (status = 200, description = "Returns the irulescan result for all submitted files.", body = [ScanFilesResponseEntry]),
        (status = 500, description = "Internal server error during scan of one or more files.", body = String)
    )
)]
async fn scan_files_handler(
    Query(params): Query<ScanFilesParams>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let no_warn = params.no_warn.unwrap_or(false);
    let exclude_empty_findings = params.exclude_empty_findings.unwrap_or(false);
    let mut response_files: Vec<ScanFilesResponseEntry> = Vec::new();
    let mut panic_occurred = false;
    let mut first_panic_message = String::new();

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
            tracing::info!("Skipping empty file '{}'", name);
             if !exclude_empty_findings {
                 response_files.push(ScanFilesResponseEntry {
                    filepath: name,
                    warning: vec![],
                    dangerous: vec![],
                });
            }
            continue;
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            let script = irulescan::preprocess_script(&script_in);
            let preprocessed_scripts = vec![(name.clone(), script)];
            scan_and_format_results(&preprocessed_scripts, no_warn, exclude_empty_findings)
        }));

        match result {
            Ok(scan_results_json) => {
                if let Some(file_results_obj) = scan_results_json.as_array().and_then(|arr| arr.get(0)).cloned() {
                    let warning: Vec<FindingDetail> = serde_json::from_value(file_results_obj.get("warning").cloned().unwrap_or_else(|| json!([]))).unwrap_or_default();
                    let dangerous: Vec<FindingDetail> = serde_json::from_value(file_results_obj.get("dangerous").cloned().unwrap_or_else(|| json!([]))).unwrap_or_default();

                    // Add result even if findings are empty, unless exclude_empty_findings is true
                     if !exclude_empty_findings || !warning.is_empty() || !dangerous.is_empty() {
                        response_files.push(ScanFilesResponseEntry {
                            filepath: name,
                            warning,
                            dangerous,
                        });
                    }
                } else if !exclude_empty_findings {
                     // Handle case where scan_and_format_results returned empty array but we don't exclude empty
                     response_files.push(ScanFilesResponseEntry {
                            filepath: name,
                            warning: vec![],
                            dangerous: vec![],
                        });
                }
            }
            Err(panic_payload) => {
                panic_occurred = true;
                let error_message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    format!("Panic during scan of file '{}': {}", name, s)
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    format!("Panic during scan of file '{}': {}", name, s)
                } else {
                    format!("Panic during scan of file '{}': Unknown reason", name)
                };
                tracing::error!("{}", error_message);
                if first_panic_message.is_empty() {
                    first_panic_message = error_message;
                }
                // Break while loop on first panic and proceed to return error
                break;
            }
        }
    }

    if panic_occurred {
        (StatusCode::INTERNAL_SERVER_ERROR, first_panic_message).into_response()
    } else {
        (StatusCode::OK, Json(response_files)).into_response()
    }
}

pub(crate) async fn run_apiserver(listen_addr: SocketAddr) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("IRULESCAN_LOG")
                .unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
    // API routes and Swagger UI
    let app = Router::new()
        .merge(SwaggerUi::new("/").url("/openapi.json", ApiDoc::openapi()))
        // API routes
        .route("/scan", post(scan_handler))
        .route("/scan/", post(scan_handler)) // trailing slash variant
        .route("/scanfiles", post(scan_files_handler))
        .route("/scanfiles/", post(scan_files_handler)) // trailing slash variant
        .layer(TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::new().include_headers(true))
        )
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10MB limit

    tracing::info!("irulescan OpenAPI listening on {}", listen_addr);
    tracing::info!("Swagger UI available at /");
    tracing::info!("OpenAPI 3.1 spec available at /openapi.json");

    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to address {}: {}", listen_addr, e);
            std::process::exit(1);
        }
    };

    let server = axum::serve(listener, app);

    match tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Failed to start irulescan API server: {}", e);
                Err(e)
            } else {
                Ok(())
            }
        }
        _ = tokio::signal::ctrl_c() => {
            Ok(())
        }
    } {
        Err(_) => std::process::exit(1),
        Ok(_) => {}
    }
}
