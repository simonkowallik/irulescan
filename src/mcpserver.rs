use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};

use rmcp::{
    Error as McpError, RoleServer, ServerHandler, model::*, schemars,
    service::RequestContext, tool,
};
//use rmcp::transport::sse_server::SseServer;
use rmcp::transport::streamable_http_server::axum::StreamableHttpServer;
use serde_json::json;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::scan_and_format_results;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanRequest {
    pub irule: String,
}

#[derive(Clone)]
pub struct Scanner;

#[tool(tool_box)]
impl Scanner {
    pub fn new() -> Self {
        Self {}
    }

    #[tool(description = "Scan an iRule for security issues")]
    async fn scan(
        &self,
        #[tool(aggr)] ScanRequest { irule }: ScanRequest,
    ) -> Result<CallToolResult, McpError> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let script = irulescan::preprocess_script(&irule);
            let preprocessed_scripts = vec![("mcpserver-request".to_string(), script)];
            // Don't apply no_warn or exclude_empty_findings as per requirements
            scan_and_format_results(&preprocessed_scripts, false, false)
        }));

        match result {
            Ok(scan_results) => {
                // Extract results for the single entry
                if let Some(result_obj) = scan_results.as_array().and_then(|arr| arr.get(0)) {
                    let content = Content::json(result_obj.clone())?;
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
impl ServerHandler for Scanner {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides an iRule scanning service. Use the 'scan' tool to check iRules for security issues.".to_string()),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![],
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        ReadResourceRequestParam { uri }: ReadResourceRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        Err(McpError::resource_not_found("resource_not_found", Some(json!({"uri": uri}))))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult {
            next_cursor: None,
            prompts: vec![],
        })
    }

    async fn get_prompt(
        &self,
        GetPromptRequestParam { name, .. }: GetPromptRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        Err(McpError::invalid_params("prompt not found", Some(json!({"name": name}))))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            next_cursor: None,
            resource_templates: Vec::new(),
        })
    }
}

pub async fn run_mcpserver(listen_addr: SocketAddr) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("IRULESCAN_LOG")
                .unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting irulescan MCP server on {}", listen_addr);

    match StreamableHttpServer::serve(listen_addr).await {
        Ok(server) => {
            let server_with_service = server.with_service(Scanner::new);
            
            tracing::info!("irulescan MCP server started successfully");
            tracing::info!("Press Ctrl+C to shut down");
            
            if let Ok(_) = tokio::signal::ctrl_c().await {
                tracing::info!("Shutting down...");
                server_with_service.cancel();
            }
        },
        Err(e) => {
            tracing::error!("Failed to start MCP server: {}", e);
            std::process::exit(1);
        }
    }
}