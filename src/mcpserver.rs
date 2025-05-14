use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};

use rmcp::{
    Error as McpError, RoleServer, ServerHandler, model::*, schemars,
    service::RequestContext, tool,
};
use rmcp::transport::streamable_http_server::axum::StreamableHttpServer;
use serde_json::json;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::scan_and_format_results;

const GOOD_PRACTICES_URI: &str = "irulescan://good-practices";
const GOOD_PRACTICES_NAME: &str = "iRule Security Good Practices";
const GOOD_PRACTICES_CONTENT: &str = include_str!("../files/good-practices.md");

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanRequest {
    pub irule: String,
}

#[derive(Clone)]
pub struct Irulescan {
    include_additional_context: bool,
}

#[tool(tool_box)]
impl Irulescan {
    pub fn new(include_additional_context: bool) -> Self {
        Self { include_additional_context }
    }

    #[tool(description = "Scan and analyse F5 iRule code for security issues")]
    async fn scan(
        &self,
        #[tool(aggr)] ScanRequest { irule }: ScanRequest,
    ) -> Result<CallToolResult, McpError> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let script = irulescan::preprocess_script(&irule);
            let preprocessed_scripts = vec![("mcpserver-request".to_string(), script)];
            // Don't apply no_warn or exclude_empty_findings
            scan_and_format_results(&preprocessed_scripts, false, false)
        }));

        match result {
            Ok(scan_results) => {
                // Extract results for the single entry, add good practices if requested
                if let Some(result_obj) = scan_results.as_array().and_then(|arr| arr.get(0)) {
                    let mut result_map = result_obj.as_object().cloned().unwrap_or_else(serde_json::Map::new);
                    if self.include_additional_context {
                        result_map.insert("good_practices".to_string(), serde_json::Value::String(GOOD_PRACTICES_CONTENT.to_string()));
                    }
                    let content = Content::json(serde_json::Value::Object(result_map))?;
                    Ok(CallToolResult::success(vec![content]))
                } else {
                    let content = Content::json(json!({"warning": [], "dangerous": []}))?;
                    Ok(CallToolResult::success(vec![content]))
                }
            },
            Err(panic_payload) => {
                let error_message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    format!("Internal server error during scan: {}", s)
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    format!("Internal server error during scan: {}", s)
                } else {
                    "Internal server error during scan: Unknown panic reason".to_string()
                };
                
                Err(McpError::internal_error("scan_error", Some(json!({"error": error_message}))))
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for Irulescan {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(r#"
This server provides an iRule scanning service powered by irulescan.
Use the 'scan' tool to check iRules for security issues.
Use the 'irulescan://good-practices' resource to get a list of iRule security best practices.
"#.to_string()),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(
                    GOOD_PRACTICES_URI.to_string(),
                    GOOD_PRACTICES_NAME.to_string(),
                )
                .no_annotation()
            ],
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        ReadResourceRequestParam { uri }: ReadResourceRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        match uri.as_str() {
            GOOD_PRACTICES_URI => {
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(GOOD_PRACTICES_CONTENT.to_string(), uri)],
                })
            }
            _ => Err(McpError::resource_not_found("resource_not_found",Some(json!({"uri": uri})))),
        }
    }
}

pub async fn run_mcpserver(listen_addr: SocketAddr, include_additional_context: bool) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("IRULESCAN_LOG")
                .unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("irulescan MCP server listening on {}", listen_addr);
    if include_additional_context {
        tracing::info!("Including good practices in the scan results on findings.");
    }

    match StreamableHttpServer::serve(listen_addr).await {
        Ok(server) => {
            let server_with_service = server.with_service(move || Irulescan::new(include_additional_context));
            if let Ok(_) = tokio::signal::ctrl_c().await {
                server_with_service.cancel();
            }
        },
        Err(e) => {
            tracing::error!("Failed to start irulescan MCP server: {}", e);
            std::process::exit(1);
        }
    }
}