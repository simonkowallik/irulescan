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

mod messages {
    pub const LITERAL_EXPECTED_DOLLAR_NO_QUOTES: &str = "literal expected, found `$`, use braces `{ .. }`";
    pub const LITERAL_EXPECTED_DOLLAR_QUOTES: &str = r#"literal expected, found `$`, use braces `{ .. }` instead of quotes `" .. "`"#;
    pub const LITERAL_EXPECTED_BRACKET_NO_QUOTES: &str = "literal expected, found `[`, use braces `{ .. }`";
    pub const LITERAL_EXPECTED_BRACKET_QUOTES: &str = r#"literal expected, found `[`, use braces `{ .. }` instead of quotes `" .. "`"#;
    pub const NON_STANDARD_ASCII_CHARS: &str = "token contains character(s) outside the standard ascii printable/whitespace set";
    pub const NON_LITERAL_COMMAND: &str = "non-literal command, cannot scan";
    pub const UNKNOWN_EVENT: &str = "event unknown";
    pub const DANGEROUS_SWITCH_BODY: &str = "dangerous switch body, use braces `{ .. }`";
    pub const MISSING_OPTIONS_TERMINATOR_SWITCH: &str = "missing options terminator `--` permits argument injection";
    pub const MISSING_OPTIONS_TERMINATOR_CLASS: &str = "missing options terminator `--` permits argument injection";
    pub const MISSING_OPTIONS_TERMINATOR_UNSET: &str = "missing options terminator `--` permits argument injection";
    pub const MISSING_OPTIONS_TERMINATOR_REGEXP: &str = "missing options terminator `--` permits argument injection";
    pub const MISSING_OPTIONS_TERMINATOR_TABLE: &str = "missing options terminator `--` permits argument injection";
    pub const DEPRECATED_COMMAND: &str = "command is deprecated";
    pub const UNSUPPORTED_COMMAND: &str = "command is unsupported";
    pub const UNSAFE_COMMAND: &str = "command is unsafe";
    pub const UNKNOWN_COMMAND: &str = "command is unknown";
    pub const BADLY_FORMED_COMMAND: &str = "command is badly formed, cannot scan code";
    pub const DANGEROUS_UNSAFE_SWITCH_BODY: &str = r"dangerous unsafe switch body, use braces `{ .. }`";
    pub const UNSAFE_CODE_BLOCK: &str = "unsafe code block, use braces `{ .. }`";
    pub const DANGEROUS_UNSAFE_CODE_BLOCK: &str = "dangerous unsafe code block, use braces `{ .. }`";
    pub const UNSAFE_EXPRESSION: &str = "unsafe expression, use braces `{ .. }`";
    pub const DANGEROUS_UNSAFE_EXPRESSION: &str = "dangerous unsafe expression, use braces `{ .. }`";
}

pub mod rstcl;
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
mod tcl;

const IRULE_COMMANDS_UNSAFE: &[&'static str] = &["uplevel", "history"];
const IRULE_EVENTS: &[&'static str] = &["ACCESS2_POLICY_EXPRESSION_EVAL", "ACCESS_ACL_ALLOWED", "ACCESS_ACL_DENIED", "ACCESS_PER_REQUEST_AGENT_EVENT", "ACCESS_POLICY_AGENT_EVENT", "ACCESS_POLICY_COMPLETED", "ACCESS_SAML_ASSERTION", "ACCESS_SAML_AUTHN", "ACCESS_SAML_SLO_REQ", "ACCESS_SAML_SLO_RESP", "ACCESS_SESSION_CLOSED", "ACCESS_SESSION_STARTED", "ADAPT_REQUEST_HEADERS", "ADAPT_REQUEST_RESULT", "ADAPT_RESPONSE_HEADERS", "ADAPT_RESPONSE_RESULT", "ANTIFRAUD_ALERT", "ANTIFRAUD_LOGIN", "ASM_REQUEST_BLOCKING", "ASM_REQUEST_DONE", "ASM_REQUEST_VIOLATION", "ASM_RESPONSE_LOGIN", "ASM_RESPONSE_VIOLATION", "AUTH_ERROR", "AUTH_FAILURE", "AUTH_RESULT", "AUTH_SUCCESS", "AUTH_WANTCREDENTIAL", "AVR_CSPM_INJECTION", "BOTDEFENSE_ACTION", "BOTDEFENSE_REQUEST", "CACHE_REQUEST", "CACHE_RESPONSE", "CACHE_UPDATE", "CATEGORY_MATCHED", "CLASSIFICATION_DETECTED", "CLIENTSSL_CLIENTCERT", "CLIENTSSL_CLIENTHELLO", "CLIENTSSL_DATA", "CLIENTSSL_HANDSHAKE", "CLIENTSSL_PASSTHROUGH", "CLIENTSSL_SERVERHELLO_SEND", "CLIENT_ACCEPTED", "CLIENT_CLOSED", "CLIENT_DATA", "CONNECTOR_OPEN", "DIAMETER_EGRESS", "DIAMETER_INGRESS", "DIAMETER_RETRANSMISSION", "DNS_REQUEST", "DNS_RESPONSE", "ECA_REQUEST_ALLOWED", "ECA_REQUEST_DENIED", "EPI_NA_CHECK_HTTP_REQUEST", "FIX_HEADER", "FIX_MESSAGE", "FLOW_INIT", "GENERICMESSAGE_EGRESS", "GENERICMESSAGE_INGRESS", "GTP_GPDU_EGRESS", "GTP_GPDU_INGRESS", "GTP_PRIME_EGRESS", "GTP_PRIME_INGRESS", "GTP_SIGNALLING_EGRESS", "GTP_SIGNALLING_INGRESS", "HTML_COMMENT_MATCHED", "HTML_TAG_MATCHED", "HTTP_CLASS_FAILED", "HTTP_CLASS_SELECTED", "HTTP_DISABLED", "HTTP_PROXY_CONNECT", "HTTP_PROXY_REQUEST", "HTTP_PROXY_RESPONSE", "HTTP_REJECT", "HTTP_REQUEST", "HTTP_REQUEST_DATA", "HTTP_REQUEST_RELEASE", "HTTP_REQUEST_SEND", "HTTP_RESPONSE", "HTTP_RESPONSE_CONTINUE", "HTTP_RESPONSE_DATA", "HTTP_RESPONSE_RELEASE", "ICAP_REQUEST", "ICAP_RESPONSE", "IN_DOSL7_ATTACK", "IVS_ENTRY_REQUEST", "IVS_ENTRY_RESPONSE", "L7CHECK_CLIENT_DATA", "L7CHECK_SERVER_DATA", "LB::class", "LB_FAILED", "LB_QUEUED", "LB_SELECTED", "MQTT_CLIENT_DATA", "MQTT_CLIENT_EGRESS", "MQTT_CLIENT_INGRESS", "MQTT_CLIENT_SHUTDOWN", "MQTT_SERVER_DATA", "MQTT_SERVER_EGRESS", "MQTT_SERVER_INGRESS", "MR_DATA", "MR_EGRESS", "MR_FAILED", "MR_INGRESS", "NAME_RESOLVED", "PCP_REQUEST", "PCP_RESPONSE", "PEM_POLICY", "PEM_SUBS_SESS_CREATED", "PEM_SUBS_SESS_DELETED", "PEM_SUBS_SESS_UPDATED", "PERSIST_DOWN", "PING_REQUEST_READY", "PING_RESPONSE_READY", "PROTOCOL_INSPECTION_MATCH", "QOE_PARSE_DONE", "RADIUS_AAA_ACCT_REQUEST", "RADIUS_AAA_ACCT_RESPONSE", "RADIUS_AAA_AUTH_REQUEST", "RADIUS_AAA_AUTH_RESPONSE", "REWRITE_REQUEST", "REWRITE_REQUEST_DONE", "REWRITE_RESPONSE", "REWRITE_RESPONSE_DONE", "RTSP_REQUEST", "RTSP_REQUEST_DATA", "RTSP_RESPONSE", "RTSP_RESPONSE_DATA", "RULE_INIT", "SA_PICKED", "SERVERSSL_CLIENTHELLO_SEND", "SERVERSSL_DATA", "SERVERSSL_HANDSHAKE", "SERVERSSL_SERVERCERT", "SERVERSSL_SERVERHELLO", "SERVER_CLOSED", "SERVER_CONNECTED", "SERVER_DATA", "SERVER_INIT", "SIP_REQUEST", "SIP_REQUEST_DONE", "SIP_REQUEST_SEND", "SIP_RESPONSE", "SIP_RESPONSE_DONE", "SIP_RESPONSE_SEND", "SOCKS_REQUEST", "STREAM_MATCHED", "TAP_REQUEST", "TDS_REQUEST", "TDS_RESPONSE", "USER_REQUEST", "USER_RESPONSE", "WS_CLIENT_DATA", "WS_CLIENT_FRAME", "WS_CLIENT_FRAME_DONE", "WS_REQUEST", "WS_RESPONSE", "WS_SERVER_DATA", "WS_SERVER_FRAME", "WS_SERVER_FRAME_DONE", "XML_CONTENT_BASED_ROUTING"];
const IRULE_COMMANDS_DEPRECATED: &[&'static str] = &["accumulate", "active_nodes", "client_addr", "client_port", "decode_uri", "findclass", "http_cookie", "http_header", "http_host", "http_method", "http_uri", "http_version", "imid", "ip_addr", "ip_protocol", "ip_tos", "ip_ttl", "link_qos", "local_addr", "local_port", "matchclass", "redirect", "remote_addr", "remote_port", "server_addr", "server_port", "urlcatblindquery", "urlcatquery", "use", "vlan_id"];
const IRULE_COMMANDS_UNSUPPORTED: &[&'static str] = &["auto_execok", "auto_import", "auto_load", "auto_mkindex", "auto_mkindex_old", "auto_qualify", "auto_reset", "bgerror", "cd", "eof", "exec", "exit", "fblocked", "fconfigure", "fcopy", "file", "fileevent", "filename", "flush", "gets", "glob", "http", "interp", "load", "memory", "namespace", "open", "package", "pid", "pkg::create", "pkg_mkindex", "pwd", "rename", "seek", "socket", "source", "tcl_findLibrary", "tell", "time", "unknown", "update", "vwait", "case", "dict", "encoding", "lrepeat", "lreverse", "pkg_mkIndex", "trace", "mcget", "scope_exists", "vwait"];
const IRULE_COMMANDS: &[&'static str] = &["active_members", "append", "array", "b64decode", "b64encode", "binary", "break", "call", "clientside", "clock", "clone", "close", "concat", "connect", "continue", "cpu", "crc32", "discard", "domain", "drop", "error", "event", "fasthash", "fi", "findstr", "format", "forward", "getfield", "global", "history", "htonl", "htons", "ifile", "incr", "info", "join", "lappend", "lasthop", "library", "lindex", "linsert", "list", "listen", "llength", "llookup", "log", "lrange", "lreplace", "lsearch", "lset", "lsort", "md5", "members", "nexthop", "node", "nodes", "ntohl", "ntohs", "peer", "pem_dtos", "persist", "pool", "priority", "puts", "rateclass", "read", "recv", "reject", "relate_client", "relate_server", "return", "rmd160", "scan", "send", "serverside", "session", "set", "sha1", "sha256", "sha384", "sha512", "sharedvar", "snat", "snatpool", "split", "string", "subst", "substr", "tcpdump", "timing", "traffic_group", "translate", "uplevel", "upvar", "variable", "virtual", "whereis"];
const IRULE_COMMANDS_NAMESPACED: &[&'static str] = &["AAA::acct_result", "AAA::acct_send", "AAA::auth_result", "AAA::auth_send", "ACCESS2::access2_proc", "ACCESS::acl", "ACCESS::disable", "ACCESS::enable", "ACCESS::ephemeral-auth", "ACCESS::flowid", "ACCESS::log", "ACCESS::oauth", "ACCESS::perflow", "ACCESS::policy", "ACCESS::respond", "ACCESS::restrict_irule_events", "ACCESS::saml", "ACCESS::session", "ACCESS::user", "ACCESS::uuid", "ACL::action", "ACL::eval", "ADAPT::allow", "ADAPT::context_create", "ADAPT::context_current", "ADAPT::context_delete_all", "ADAPT::context_name", "ADAPT::context_static", "ADAPT::enable", "ADAPT::preview_size", "ADAPT::result", "ADAPT::select", "ADAPT::service_down_action", "ADAPT::timeout", "ADFS_PROXY::disable", "ADFS_PROXY::enable", "ADFS_PROXY::flush", "ADFS_PROXY::metadata", "ADFS_PROXY::payload", "ADFS_PROXY::select", "ADFS_PROXY::send", "AES::decrypt", "AES::encrypt", "AES::key", "AM::age", "AM::application", "AM::cache", "AM::disable", "AM::expires", "AM::media_playlist", "AM::policy_node", "ANTIFRAUD::alert_additional_info", "ANTIFRAUD::alert_bait_signatures", "ANTIFRAUD::alert_component", "ANTIFRAUD::alert_defined_value", "ANTIFRAUD::alert_details", "ANTIFRAUD::alert_device_id", "ANTIFRAUD::alert_expected_value", "ANTIFRAUD::alert_fingerprint", "ANTIFRAUD::alert_forbidden_added_element", "ANTIFRAUD::alert_guid", "ANTIFRAUD::alert_html", "ANTIFRAUD::alert_http_referrer", "ANTIFRAUD::alert_id", "ANTIFRAUD::alert_license_id", "ANTIFRAUD::alert_min", "ANTIFRAUD::alert_origin", "ANTIFRAUD::alert_resolved_value", "ANTIFRAUD::alert_score", "ANTIFRAUD::alert_transaction_data", "ANTIFRAUD::alert_transaction_id", "ANTIFRAUD::alert_type", "ANTIFRAUD::alert_username", "ANTIFRAUD::alert_view_id", "ANTIFRAUD::client_id", "ANTIFRAUD::device_id", "ANTIFRAUD::disable", "ANTIFRAUD::disable_alert", "ANTIFRAUD::disable_app_layer_encryption", "ANTIFRAUD::disable_auto_transactions", "ANTIFRAUD::disable_injection", "ANTIFRAUD::disable_malware", "ANTIFRAUD::disable_phishing", "ANTIFRAUD::enable", "ANTIFRAUD::enable_log", "ANTIFRAUD::fingerprint", "ANTIFRAUD::geo", "ANTIFRAUD::guid", "ANTIFRAUD::result", "ANTIFRAUD::username", "ASM::action", "ASM::captcha", "ASM::captcha_age", "ASM::captcha_status", "ASM::client_ip", "ASM::conviction", "ASM::cortex_event_id", "ASM::cortex_vid", "ASM::deception", "ASM::details", "ASM::disable", "ASM::enable", "ASM::fingerprint", "ASM::flush", "ASM::is_authenticated", "ASM::login_status", "ASM::metadata", "ASM::microservice", "ASM::payload", "ASM::policy", "ASM::raise", "ASM::select", "ASM::send", "ASM::severity", "ASM::signature", "ASM::status", "ASM::support_id", "ASM::threat_campaign", "ASM::unblock", "ASM::uncaptcha", "ASM::username", "ASM::violation", "ASM::violation_data", "ASN1::decode", "ASN1::element", "ASN1::encode", "AUTH::abort", "AUTH::authenticate", "AUTH::authenticate_continue", "AUTH::cert_credential", "AUTH::cert_issuer_credential", "AUTH::last_event_session_id", "AUTH::password_credential", "AUTH::response_data", "AUTH::ssl_cc_ldap_status", "AUTH::ssl_cc_ldap_username", "AUTH::start", "AUTH::status", "AUTH::subscribe", "AUTH::unsubscribe", "AUTH::username_credential", "AUTH::wantcredential_prompt", "AUTH::wantcredential_prompt_style", "AUTH::wantcredential_type", "AVR::disable", "AVR::disable_cspm_injection", "AVR::enable", "AVR::log", "BIGPROTO::enable_fix_reset", "BIGTCP::release_flow", "BOTDEFENSE::action", "BOTDEFENSE::bot_anomalies", "BOTDEFENSE::bot_categories", "BOTDEFENSE::bot_name", "BOTDEFENSE::bot_signature", "BOTDEFENSE::bot_signature_category", "BOTDEFENSE::captcha_age", "BOTDEFENSE::captcha_status", "BOTDEFENSE::client_class", "BOTDEFENSE::client_type", "BOTDEFENSE::cookie_age", "BOTDEFENSE::cookie_status", "BOTDEFENSE::cs_allowed", "BOTDEFENSE::cs_attribute", "BOTDEFENSE::cs_possible", "BOTDEFENSE::device_id", "BOTDEFENSE::disable", "BOTDEFENSE::enable", "BOTDEFENSE::intent", "BOTDEFENSE::micro_service", "BOTDEFENSE::previous_action", "BOTDEFENSE::previous_request_age", "BOTDEFENSE::previous_support_id", "BOTDEFENSE::reason", "BOTDEFENSE::support_id", "BWC::color", "BWC::debug", "BWC::mark", "BWC::measure", "BWC::policy", "BWC::pps", "BWC::priority", "BWC::rate", "CACHE::accept_encoding", "CACHE::age", "CACHE::disable", "CACHE::disabled", "CACHE::enable", "CACHE::expire", "CACHE::fresh", "CACHE::header", "CACHE::headers", "CACHE::hits", "CACHE::payload", "CACHE::priority", "CACHE::statskey", "CACHE::trace", "CACHE::uri", "CACHE::useragent", "CACHE::userkey", "CATEGORY::analytics", "CATEGORY::filetype", "CATEGORY::lookup", "CATEGORY::matchtype", "CATEGORY::result", "CATEGORY::safesearch", "CGC::port", "CGC::sni", "CLASSIFICATION::app", "CLASSIFICATION::category", "CLASSIFICATION::disable", "CLASSIFICATION::enable", "CLASSIFICATION::protocol", "CLASSIFICATION::result", "CLASSIFICATION::urlcat", "CLASSIFICATION::username", "CLASSIFY::application", "CLASSIFY::category", "CLASSIFY::defer", "CLASSIFY::disable", "CLASSIFY::urlcat", "CLASSIFY::username", "COMPRESS::buffer_size", "COMPRESS::disable", "COMPRESS::enable", "COMPRESS::gzip", "COMPRESS::method", "COMPRESS::nodelay", "CONNECTOR::disable", "CONNECTOR::enable", "CONNECTOR::profile", "CONNECTOR::remap", "CRYPTO::decrypt", "CRYPTO::encrypt", "CRYPTO::hash", "CRYPTO::keygen", "CRYPTO::sign", "CRYPTO::verify", "DATAGRAM::dns", "DATAGRAM::ip", "DATAGRAM::ip6", "DATAGRAM::l2", "DATAGRAM::tcp", "DATAGRAM::udp", "DECOMPRESS::disable", "DECOMPRESS::enable", "DEMANGLE::disable", "DEMANGLE::enable", "DHCP::version", "DHCPv4::chaddr", "DHCPv4::ciaddr", "DHCPv4::drop", "DHCPv4::giaddr", "DHCPv4::hlen", "DHCPv4::hops", "DHCPv4::htype", "DHCPv4::len", "DHCPv4::opcode", "DHCPv4::option", "DHCPv4::reject", "DHCPv4::secs", "DHCPv4::siaddr", "DHCPv4::type", "DHCPv4::xid", "DHCPv4::yiaddr", "DHCPv6::drop", "DHCPv6::hop_count", "DHCPv6::len", "DHCPv6::link_address", "DHCPv6::msg_type", "DHCPv6::option", "DHCPv6::peer_address", "DHCPv6::reject", "DHCPv6::transaction_id", "DIAG::error", "DIAG::panic", "DIAMETER::avp", "DIAMETER::command", "DIAMETER::disconnect", "DIAMETER::drop", "DIAMETER::dynamic_route_insertion", "DIAMETER::dynamic_route_lookup", "DIAMETER::header", "DIAMETER::host", "DIAMETER::is_request", "DIAMETER::is_response", "DIAMETER::is_retransmission", "DIAMETER::length", "DIAMETER::message", "DIAMETER::payload", "DIAMETER::persist", "DIAMETER::realm", "DIAMETER::respond", "DIAMETER::result", "DIAMETER::retransmission", "DIAMETER::retransmission_default", "DIAMETER::retransmission_reason", "DIAMETER::retransmit", "DIAMETER::retry", "DIAMETER::route_status", "DIAMETER::session", "DIAMETER::skip_capabilities_exchange", "DIAMETER::state", "DNS::additional", "DNS::answer", "DNS::authority", "DNS::class", "DNS::disable", "DNS::drop", "DNS::edns0", "DNS::enable", "DNS::header", "DNS::is_wideip", "DNS::last_act", "DNS::len", "DNS::log", "DNS::name", "DNS::origin", "DNS::ptype", "DNS::query", "DNS::question", "DNS::rdata", "DNS::return", "DNS::rpz_policy", "DNS::rr", "DNS::scrape", "DNS::tsig", "DNS::ttl", "DNS::type", "DNSMSG::header", "DNSMSG::record", "DNSMSG::section", "DOSL7::disable", "DOSL7::enable", "DOSL7::health", "DOSL7::is_ip_slowdown", "DOSL7::is_mitigated", "DOSL7::profile", "DOSL7::slowdown", "DSLITE::remote_addr", "ECA::client_machine_name", "ECA::disable", "ECA::domainname", "ECA::enable", "ECA::flush", "ECA::metadata", "ECA::payload", "ECA::select", "ECA::send", "ECA::status", "ECA::username", "FIX::tag", "FLOW::create_related", "FLOW::idle_duration", "FLOW::idle_timeout", "FLOW::peer", "FLOW::priority", "FLOW::refresh", "FLOW::this", "FLOWTABLE::count", "FLOWTABLE::limit", "FTP::allow_active_mode", "FTP::disable", "FTP::enable", "FTP::enforce_tls_session_reuse", "FTP::ftps_mode", "FTP::port", "GENERICMESSAGE::message", "GENERICMESSAGE::peer", "GENERICMESSAGE::route", "GTM::active_members", "GTM::cname", "GTM::discard", "GTM::drop", "GTM::forward", "GTM::host", "GTM::matchregion", "GTM::members", "GTM::nodes_up", "GTM::noerror", "GTM::path", "GTM::persist", "GTM::pool", "GTM::pools", "GTM::qos_score", "GTM::qos_weight", "GTM::rcode", "GTM::reject", "GTM::ttl", "GTM::uptime", "GTM::whereami", "GTM::whereis", "GTM::whoami", "GTM::wideip", "GTP::clone", "GTP::discard", "GTP::forward", "GTP::header", "GTP::ie", "GTP::length", "GTP::message", "GTP::new", "GTP::parse", "GTP::payload", "GTP::respond", "GTP::tunnel", "GZIP::disable", "GZIP::enable", "HA::status", "HSL::open", "HSL::send", "HTML::comment", "HTML::disable", "HTML::enable", "HTML::tag", "HTTP2::active", "HTTP2::concurrency", "HTTP2::disable", "HTTP2::disconnect", "HTTP2::enable", "HTTP2::header", "HTTP2::push", "HTTP2::requests", "HTTP2::stream", "HTTP2::version", "HTTP::close", "HTTP::collect", "HTTP::cookie", "HTTP::disable", "HTTP::enable", "HTTP::fallback", "HTTP::has_responded", "HTTP::header", "HTTP::host", "HTTP::hsts", "HTTP::is_keepalive", "HTTP::is_redirect", "HTTP::method", "HTTP::passthrough_reason", "HTTP::password", "HTTP::path", "HTTP::payload", "HTTP::proxy", "HTTP::query", "HTTP::redirect", "HTTP::reject_reason", "HTTP::release", "HTTP::request", "HTTP::request_num", "HTTP::respond", "HTTP::response", "HTTP::retry", "HTTP::status", "HTTP::uri", "HTTP::username", "HTTP::version", "ICAP::header", "ICAP::method", "ICAP::status", "ICAP::uri", "IKE::abort", "IKE::auth_success", "IKE::cert", "IKE::resume", "IKE::san_dirname", "IKE::san_dns", "IKE::san_ediparty", "IKE::san_email", "IKE::san_ipadd", "IKE::san_othername", "IKE::san_rid", "IKE::san_uri", "IKE::san_x400", "IKE::subjectAltName", "ILX::call", "ILX::disable", "ILX::enable", "ILX::flush", "ILX::init", "ILX::metadata", "ILX::notify", "ILX::payload", "ILX::select", "ILX::send", "IMAP::activation_mode", "IMAP::disable", "IMAP::enable", "IP::addr", "IP::client_addr", "IP::df", "IP::hops", "IP::idle_timeout", "IP::intelligence", "IP::local_addr", "IP::protocol", "IP::remote_addr", "IP::reputation", "IP::server_addr", "IP::stats", "IP::tos", "IP::ttl", "IP::version", "IPFIX::destination", "IPFIX::msg", "IPFIX::template", "ISESSION::deduplication", "ISESSION::optimized", "ISTATS::get", "ISTATS::incr", "ISTATS::remove", "ISTATS::set", "IVS_ENTRY::result", "L7CHECK::protocol", "LB::bias", "LB::class", "LB::command", "LB::connect", "LB::connlimit", "LB::context_id", "LB::detach", "LB::down", "LB::dst_tag", "LB::enable_decisionlog", "LB::mode", "LB::persist", "LB::prime", "LB::queue", "LB::reselect", "LB::select", "LB::server", "LB::snat", "LB::src_tag", "LB::status", "LB::up", "LDAP::activation_mode", "LDAP::disable", "LDAP::enable", "LIBUV::disable", "LIBUV::enable", "LIBUV::flush", "LIBUV::metadata", "LIBUV::payload", "LIBUV::select", "LIBUV::send", "LINE::get", "LINE::set", "LINK::lasthop", "LINK::nexthop", "LINK::qos", "LINK::vlan_id", "LISTEN::allow", "LISTEN::bind", "LISTEN::proto", "LISTEN::server", "LISTEN::timeout", "LSN::address", "LSN::disable", "LSN::inbound", "LSN::inbound-entry", "LSN::persistence", "LSN::persistence-entry", "LSN::pool", "LSN::port", "MESSAGE::field", "MESSAGE::proto", "MESSAGE::type", "MQTT::clean_session", "MQTT::client_id", "MQTT::collect", "MQTT::disable", "MQTT::disconnect", "MQTT::drop", "MQTT::dup", "MQTT::enable", "MQTT::insert", "MQTT::keep_alive", "MQTT::length", "MQTT::message", "MQTT::packet_id", "MQTT::password", "MQTT::payload", "MQTT::protocol_name", "MQTT::protocol_version", "MQTT::qos", "MQTT::release", "MQTT::replace", "MQTT::respond", "MQTT::retain", "MQTT::return_code", "MQTT::return_code_list", "MQTT::session_present", "MQTT::topic", "MQTT::type", "MQTT::username", "MQTT::will", "MR::always_match_port", "MR::available_for_routing", "MR::collect", "MR::connect_back_port", "MR::connection_instance", "MR::connection_mode", "MR::equivalent_transport", "MR::flow_id", "MR::ignore_peer_port", "MR::instance", "MR::max_retries", "MR::message", "MR::payload", "MR::peer", "MR::prime", "MR::protocol", "MR::release", "MR::restore", "MR::retry", "MR::return", "MR::store", "MR::stream", "MR::transport", "NAME::lookup", "NAME::response", "NETFLOW::disable", "NETFLOW::enable", "NETWORKACCESS::snat", "NSH::chain", "NSH::context", "NSH::md1", "NSH::mocksf", "NSH::path_id", "NSH::service_index", "NTLM::disable", "NTLM::enable", "NTLM::flush", "NTLM::metadata", "NTLM::payload", "NTLM::select", "NTLM::send", "NULL::disable", "NULL::enable", "OAUTHPLUGIN::disable", "OAUTHPLUGIN::enable", "OAUTHPLUGIN::flush", "OAUTHPLUGIN::metadata", "OAUTHPLUGIN::payload", "OAUTHPLUGIN::select", "OAUTHPLUGIN::send", "OFFBOX::proxy_authorization", "OFFBOX::proxy_enabled", "OFFBOX::proxy_host", "OFFBOX::proxy_port", "OFFBOX::request", "ONECONNECT::detach", "ONECONNECT::label", "ONECONNECT::reuse", "ONECONNECT::select", "PCP::reject", "PCP::request", "PCP::response", "PEM::disable", "PEM::enable", "PEM::flow", "PEM::policy", "PEM::qoe", "PEM::session", "PEM::subscriber", "POLICY::controls", "POLICY::names", "POLICY::rules", "POLICY::targets", "POP3::activation_mode", "POP3::disable", "POP3::enable", "PPP::status", "PPTP::disable", "PPTP::enable", "PROFILE::access", "PROFILE::add", "PROFILE::antifraud", "PROFILE::antserver_class", "PROFILE::ap_ai", "PROFILE::api_protection", "PROFILE::apm_ivs", "PROFILE::apm_sso_class", "PROFILE::apmd_class", "PROFILE::appchk", "PROFILE::auth", "PROFILE::avr", "PROFILE::bigproto", "PROFILE::bot_defense", "PROFILE::bot_defense_asm", "PROFILE::cifs", "PROFILE::classification", "PROFILE::clientldap", "PROFILE::clientssl", "PROFILE::cloud_security_services_crstuf", "PROFILE::cloud_security_services_globapp", "PROFILE::cloud_security_services_tap", "PROFILE::connectivity", "PROFILE::connector", "PROFILE::csd", "PROFILE::device_id", "PROFILE::dhcpv4", "PROFILE::dhcpv6", "PROFILE::diameter", "PROFILE::diameter_endpoint", "PROFILE::diameterrouter", "PROFILE::diametersession", "PROFILE::dns", "PROFILE::dns_acceleration", "PROFILE::doh_proxy", "PROFILE::doh_server", "PROFILE::dos", "PROFILE::dpi", "PROFILE::eam", "PROFILE::eca", "PROFILE::etherip", "PROFILE::euie", "PROFILE::exchange", "PROFILE::exists", "PROFILE::fastL4", "PROFILE::fasthttp", "PROFILE::fec", "PROFILE::fix", "PROFILE::ftp", "PROFILE::genericmsg", "PROFILE::geneve", "PROFILE::georedundancy", "PROFILE::gre", "PROFILE::gtp", "PROFILE::htconnector_class", "PROFILE::html", "PROFILE::http", "PROFILE::http2", "PROFILE::http3", "PROFILE::http_proxy_connect", "PROFILE::httpcompression", "PROFILE::httprouter", "PROFILE::httpsecurity", "PROFILE::ibd", "PROFILE::icap", "PROFILE::ilx", "PROFILE::imap", "PROFILE::ipip", "PROFILE::ipother", "PROFILE::ips", "PROFILE::ipsec", "PROFILE::ipsecalg", "PROFILE::isession", "PROFILE::list", "PROFILE::lucenedb_class", "PROFILE::lw4o6", "PROFILE::map", "PROFILE::mapi", "PROFILE::mapt", "PROFILE::messagerouter", "PROFILE::mqtt", "PROFILE::mqttrouter", "PROFILE::mqttsession", "PROFILE::mr_ratelimit", "PROFILE::netflow", "PROFILE::ntlm", "PROFILE::oauth", "PROFILE::oauthdb_class", "PROFILE::oauthplugin", "PROFILE::ocsp_responder", "PROFILE::oneconnect", "PROFILE::passthruwocplugin", "PROFILE::persist", "PROFILE::ping_agent_class", "PROFILE::pingaccess", "PROFILE::pluginclass", "PROFILE::pop3", "PROFILE::ppp", "PROFILE::pptp", "PROFILE::profile", "PROFILE::pua_ldap", "PROFILE::pua_radius", "PROFILE::qoe", "PROFILE::quic", "PROFILE::radius", "PROFILE::radius_aaa", "PROFILE::rba", "PROFILE::remotedesktop", "PROFILE::reqlog", "PROFILE::requestadapt", "PROFILE::responseadapt", "PROFILE::rewrite", "PROFILE::rtsp", "PROFILE::satellite", "PROFILE::scim", "PROFILE::sctp", "PROFILE::serverldap", "PROFILE::serverssl", "PROFILE::service", "PROFILE::sipp", "PROFILE::siprouter", "PROFILE::sipsession", "PROFILE::smtp", "PROFILE::smtps", "PROFILE::socket", "PROFILE::socks", "PROFILE::splitsessionclient", "PROFILE::splitsessionserver", "PROFILE::spm", "PROFILE::srdf", "PROFILE::ssh", "PROFILE::sso", "PROFILE::statistics", "PROFILE::stream", "PROFILE::subscriber_mgmt", "PROFILE::tcp", "PROFILE::tcpanalytics", "PROFILE::tcpforward", "PROFILE::tcpreassemblecs", "PROFILE::tcpreassembless", "PROFILE::tdr", "PROFILE::tftp", "PROFILE::tmi", "PROFILE::traffic_acceleration", "PROFILE::tunnel", "PROFILE::udp", "PROFILE::urldb_class", "PROFILE::v6rd", "PROFILE::vdi", "PROFILE::vxlan", "PROFILE::wccpgre", "PROFILE::webacceleration", "PROFILE::websecurity", "PROFILE::websocket", "PROFILE::webssh", "PROFILE::xml", "PROTOCOL_INSPECTION::disable", "PROTOCOL_INSPECTION::id", "PSC::aaa_reporting_interval", "PSC::attr", "PSC::calling_id", "PSC::imeisv", "PSC::imsi", "PSC::ip_address", "PSC::lease_time", "PSC::policy", "PSC::subscriber_id", "PSC::tower_id", "PSC::user_name", "PSM::FTP::disable", "PSM::FTP::enable", "PSM::HTTP::disable", "PSM::HTTP::enable", "PSM::SMTP::disable", "PSM::SMTP::enable", "QOE::disable", "QOE::enable", "QOE::video", "QUIC::abort", "QUIC::close", "RADIUS::avp", "RADIUS::code", "RADIUS::id", "RADIUS::rtdom", "RADIUS::subscriber", "RELATE::clientflow", "RELATE::proto", "RELATE::serverflow", "RESOLV::lookup", "RESOLVER::name_lookup", "RESOLVER::summarize", "REST::send", "REWRITE::disable", "REWRITE::enable", "REWRITE::payload", "REWRITE::post_process", "RISK::tls_fingerprint", "ROUTE::age", "ROUTE::bandwidth", "ROUTE::clear", "ROUTE::cwnd", "ROUTE::domain", "ROUTE::expiration", "ROUTE::mtu", "ROUTE::rtt", "ROUTE::rttvar", "RTSP::collect", "RTSP::header", "RTSP::method", "RTSP::msg_source", "RTSP::payload", "RTSP::release", "RTSP::respond", "RTSP::status", "RTSP::uri", "RTSP::version", "SAAS::proxy_authorization", "SCTP::client_port", "SCTP::collect", "SCTP::local_port", "SCTP::mss", "SCTP::payload", "SCTP::ppi", "SCTP::release", "SCTP::remote_port", "SCTP::respond", "SCTP::rto_initial", "SCTP::rto_max", "SCTP::rto_min", "SCTP::sack_timeout", "SCTP::server_port", "SDP::field", "SDP::media", "SDP::session_id", "SIP::call_id", "SIP::discard", "SIP::from", "SIP::header", "SIP::message", "SIP::method", "SIP::payload", "SIP::persist", "SIP::record-route", "SIP::record_route", "SIP::respond", "SIP::response", "SIP::route", "SIP::route_status", "SIP::to", "SIP::uri", "SIP::via", "SIPALG::hairpin", "SIPALG::hairpin_default", "SIPALG::nonregister_subscriber_listener", "SMTPS::activation_mode", "SMTPS::disable", "SMTPS::enable", "SOCKS::allowed", "SOCKS::destination", "SOCKS::version", "SSL::allow_dynamic_record_sizing", "SSL::allow_nonssl", "SSL::alpn", "SSL::authenticate", "SSL::c3d", "SSL::cert", "SSL::cert_constraint", "SSL::cipher", "SSL::clientrandom", "SSL::collect", "SSL::disable", "SSL::enable", "SSL::extensions", "SSL::forward_proxy", "SSL::handshake", "SSL::is_renegotiation_secure", "SSL::maximum_record_size", "SSL::mode", "SSL::modssl_sessionid_headers", "SSL::payload", "SSL::profile", "SSL::release", "SSL::renegotiate", "SSL::respond", "SSL::secure_renegotiation", "SSL::session", "SSL::sessionid", "SSL::sessionsecret", "SSL::sessionticket", "SSL::sni", "SSL::tls13_secret", "SSL::unclean_shutdown", "SSL::verify_result", "STATS::get", "STATS::incr", "STATS::set", "STATS::setmax", "STATS::setmin", "STREAM::disable", "STREAM::enable", "STREAM::encoding", "STREAM::expression", "STREAM::match", "STREAM::max_matchsize", "STREAM::replace", "TAP::action", "TAP::build_request", "TAP::cdn_host", "TAP::cdn_path", "TAP::classify_other", "TAP::config", "TAP::default_pool", "TAP::eventid", "TAP::free_default_pool", "TAP::grabber_url", "TAP::ingress_endpoint_ssl_enabled", "TAP::insight", "TAP::insight_requested", "TAP::is_jsevent_forward", "TAP::js_event_dns_resolver", "TAP::js_event_host", "TAP::js_event_path", "TAP::js_event_ssl_profile", "TAP::js_event_url", "TAP::js_reporting_proxy_used", "TAP::license_validation", "TAP::reason", "TAP::release_request", "TAP::score", "TAP::tap_token", "TAP::token_from_asm_sent", "TAP::vid", "TCP::abc", "TCP::analytics", "TCP::autowin", "TCP::bandwidth", "TCP::client_port", "TCP::close", "TCP::collect", "TCP::congestion", "TCP::delayed_ack", "TCP::dsack", "TCP::earlyrxmit", "TCP::ecn", "TCP::enhanced_loss_recovery", "TCP::idletime", "TCP::keepalive", "TCP::limxmit", "TCP::local_port", "TCP::lossfilter", "TCP::lossfilterburst", "TCP::lossfilterrate", "TCP::mss", "TCP::nagle", "TCP::naglemode", "TCP::naglestate", "TCP::notify", "TCP::offset", "TCP::option", "TCP::pacing", "TCP::payload", "TCP::proxybuffer", "TCP::proxybufferhigh", "TCP::proxybufferlow", "TCP::push_flag", "TCP::rcv_scale", "TCP::rcv_size", "TCP::recvwnd", "TCP::release", "TCP::remote_port", "TCP::respond", "TCP::rexmt_thresh", "TCP::rt_metrics_timeout", "TCP::rto", "TCP::rtt", "TCP::rttvar", "TCP::sendbuf", "TCP::server_port", "TCP::setmss", "TCP::snd_cwnd", "TCP::snd_scale", "TCP::snd_ssthresh", "TCP::snd_wnd", "TCP::syn_cookie", "TCP::syn_hdr_size", "TCP::syn_wnd_size", "TCP::unused_port", "TMIREQLOG::disable", "TMIREQLOG::enable", "TMM::cmp_count", "TMM::cmp_group", "TMM::cmp_groups", "TMM::cmp_primary_group", "TMM::cmp_unit", "UDP::client_port", "UDP::debug_queue", "UDP::drop", "UDP::hold", "UDP::local_port", "UDP::max_buf_pkts", "UDP::max_rate", "UDP::mss", "UDP::payload", "UDP::release", "UDP::remote_port", "UDP::respond", "UDP::sendbuffer", "UDP::server_port", "UDP::unused_port", "URI::basename", "URI::compare", "URI::decode", "URI::encode", "URI::host", "URI::path", "URI::port", "URI::protocol", "URI::query", "VALIDATE::protocol", "VDI::cmp_redirect", "VDI::disable", "VDI::enable", "VDI::flush", "VDI::metadata", "VDI::payload", "VDI::select", "VDI::send", "VPN::disable", "VPN::enable", "WAM::disable", "WAM::enable", "WEBSSH::disable", "WEBSSH::enable", "WEBSSH::flush", "WEBSSH::metadata", "WEBSSH::payload", "WEBSSH::select", "WEBSSH::send", "WEBSSO::disable", "WEBSSO::enable", "WEBSSO::select", "WS::collect", "WS::disconnect", "WS::enabled", "WS::frame", "WS::masking", "WS::message", "WS::payload", "WS::payload_ivs", "WS::payload_processing", "WS::release", "WS::request", "WS::response", "X509::cert_fields", "X509::extensions", "X509::hash", "X509::issuer", "X509::not_valid_after", "X509::not_valid_before", "X509::pem2der", "X509::serial_number", "X509::signature_algorithm", "X509::subject", "X509::subject_public_key", "X509::subject_public_key_RSA_bits", "X509::subject_public_key_type", "X509::verify_cert_error_string", "X509::version", "X509::whole", "XLAT::listen", "XLAT::listen_lifetime", "XLAT::src_addr", "XLAT::src_config", "XLAT::src_endpoint_reservation", "XLAT::src_nat_valid_range", "XLAT::src_port", "XML::disable", "XML::enable", "XML::flush", "XML::metadata", "XML::payload", "XML::select", "XML::send"];


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
    SwitchBodyRegex,
}

fn check_literal<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>, line_number: usize) -> Vec<CheckResult<'a>> {
    let token_str = token.val;
    assert!(token_str.len() > 0);
    return if token_str.chars().nth(0) == Some('{') {
        vec![]
    } else if token_str.contains('$') {
        if token_str.chars().nth(0) == Some('"') {
            vec![Danger(ctx, messages::LITERAL_EXPECTED_DOLLAR_QUOTES, token_str, line_number)]
        } else {
            vec![Danger(ctx, messages::LITERAL_EXPECTED_DOLLAR_NO_QUOTES, token_str, line_number)]
        }
    } else if token_str.contains('[') {
        if token_str.chars().nth(0) == Some('"') {
            vec![Danger(ctx, messages::LITERAL_EXPECTED_BRACKET_QUOTES, token_str, line_number)]
        } else {
            vec![Danger(ctx, messages::LITERAL_EXPECTED_BRACKET_NO_QUOTES, token_str, line_number)]
        }
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
                messages::NON_STANDARD_ASCII_CHARS,
                token.val, // The problematic token\'s value
                command_line_number, // Use the command\'s line number for this warning
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
        results.push(Warn(ctx, messages::NON_LITERAL_COMMAND, tokens[0].val, line_number));
        return results;
    }
    // Now check the command-specific interpretation of arguments etc
    let param_types = match tokens[0].val {
        // tmconf: ltm rule <name> { }
        "ltm" => vec![Code::Literal, Code::Literal, Code::Block],
        // tmconf: rule <name> { }
        "rule" => vec![Code::Literal, Code::Block],
        // iRule when
        "when" => {
            // check <event_name> is part of IRULE_EVENTS
            if !IRULE_EVENTS.contains(&tokens[1].val) {
                results.push(Warn(ctx, messages::UNKNOWN_EVENT, tokens[1].val, line_number));
            }
            match tokens.len() {
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
            }
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
        //list: list itself doesn't treat its arguments as anything in particular, but it does format them into items in a list. In a list, \ " and { operate the same way they do in Tcl. Tcl is designed this way so that a list is a properly-formatted command.
        //set: ( accesses a variable in an array.
        //string match: *, ?, [, and \ have special meaning.
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
            let mut regex_mode = false;
            let mut i = 1;
            let mut param_types: Vec<Code> = vec![];
            while i < tokens.len() {
                match tokens[i].val {
                    "-exact" | "-glob" => {
                        param_types.extend_from_slice(&vec![Code::Literal]);
                        i += 1;
                    }
                    "-regexp" => {
                        param_types.extend_from_slice(&vec![Code::Literal]);
                        regex_mode = true;
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
                    messages::MISSING_OPTIONS_TERMINATOR_SWITCH,
                    tokens[i].val, line_number // Line of the switch command
                ));
            }
            // The check for \"Dangerous unquoted switch body\" refers to the structure of the switch command\'s arguments.
            // If tokens[i] is the string argument, its line number is implicitly that of the overall command.
            // If the body (tokens[i+1]) is problematic, it\'s still part of this command line.
            if (tokens.len() - i) != 2 { // This check might be too simplistic for line numbers if args are on new lines
                results.push(Danger(ctx, messages::DANGEROUS_SWITCH_BODY, tokens[i].val, line_number));
            }
            if regex_mode {
                // If regex mode, the body's first parameter is a regex
                param_types.extend_from_slice(&vec![Code::Normal, Code::SwitchBodyRegex]);
            } else {
                // normal switch body
                param_types.extend_from_slice(&vec![Code::Normal, Code::SwitchBody]);
            }
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
                    messages::MISSING_OPTIONS_TERMINATOR_CLASS,
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
                    messages::MISSING_OPTIONS_TERMINATOR_UNSET,
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
                    messages::MISSING_OPTIONS_TERMINATOR_REGEXP,
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
                    messages::MISSING_OPTIONS_TERMINATOR_TABLE,
                    tokens[i].val, line_number // Line of the table command
                ));
            }
            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        }
        // default
        _ => {
            // Check if command is deprecated, unsupported, or unsafe
            if IRULE_COMMANDS_DEPRECATED.contains(&tokens[0].val) {
                results.push(Warn(ctx, messages::DEPRECATED_COMMAND, tokens[0].val, line_number));
            } else if IRULE_COMMANDS_UNSUPPORTED.contains(&tokens[0].val) {
                results.push(Warn(ctx, messages::UNSUPPORTED_COMMAND, tokens[0].val, line_number));
            } else if IRULE_COMMANDS_UNSAFE.contains(&tokens[0].val) {
                results.push(Danger(ctx, messages::UNSAFE_COMMAND, tokens[0].val, line_number));
            } else if IRULE_COMMANDS_NAMESPACED.contains(&tokens[0].val) {
                // pass
            } else if IRULE_COMMANDS.contains(&tokens[0].val) {
                // pass
            } else {
                results.push(Warn(ctx, messages::UNKNOWN_COMMAND, tokens[0].val, line_number));
            }

            iter::repeat(Code::Normal).take(tokens.len() - 1).collect()
        },
    };
    if param_types.len() != tokens.len() - 1 {
        results.push(Danger(
            ctx,
            messages::BADLY_FORMED_COMMAND,
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
            Code::SwitchBody => check_switch_body(ctx, param, false, line_number), // Same for switch body
            Code::SwitchBodyRegex => check_switch_body(ctx, param, true, line_number), // Same for switch body
            Code::Expr => check_expr(ctx, param, line_number), // Same for expr
            Code::Literal => check_literal(ctx, param, line_number), // Literal check uses current command's line
            Code::Normal => vec![],
        };
        results.extend(check_results.into_iter());
    }
    return results;
}

/// Scans a switch body (i.e. should be quoted) for danger
// base_line_number is the line number of the `switch` command itself.
fn check_switch_body<'a, 'b>(ctx: &'a str, token: &'b rstcl::TclToken<'a>, regex_mode: bool, base_line_number: usize) -> Vec<CheckResult<'a>> {
    let body_str = token.val;
    if !(body_str.starts_with("{") && body_str.ends_with("}")) {
        // This finding is about the switch body token itself, so use base_line_number
        return vec![Danger(ctx, messages::DANGEROUS_UNSAFE_SWITCH_BODY, body_str, base_line_number)];
    }
    // Body isn\'t inherently dangerous, let\'s check body elements
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
                if regex_mode {
                    // in regex mode 1st token might look like tcl cmds or vars but is a regex and interpreted as such by tcl
                    let results = vec![];
                    all_results.extend(results.into_iter());
                } else {
                    // non regex mode: 1st token expected to be literal
                    let results = check_literal(ctx, inner_token, actual_line_number);
                    all_results.extend(results.into_iter());
                }
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
            true => Warn(ctx, messages::UNSAFE_CODE_BLOCK, block_str, base_line_number),
            false => Danger(ctx, messages::DANGEROUS_UNSAFE_CODE_BLOCK, block_str, base_line_number),
        }];
    }
    // Block isn\\\'t inherently dangerous, let\\\'s check functions inside the block
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
        results.push(match is_safe_val(token) { // is_safe_val doesn\\\'t use line_number
            true => Warn(ctx, messages::UNSAFE_EXPRESSION, expr_str, base_line_number),
            false => Danger(ctx, messages::DANGEROUS_UNSAFE_EXPRESSION, expr_str, base_line_number),
        });
        return results;
    };
    // Expr isn\'t inherently dangerous, let\'s check functions inside the expr
    assert!(token.val.starts_with("{") && token.val.ends_with("}"));
    let expr_content_str = &token.val[1..token.val.len() - 1];
    let (parse_result, remaining) = rstcl::parse_expr(expr_content_str); // parse_expr gives line_number 1 for the expression itself.
    if parse_result.tokens.len() != 1 || !remaining.is_empty() {
        panic!(
            "rstcl::parse_expr post-condition violated: \
            Expected tokens.len() to be 1, but got >{}<. \
            Expected remaining string to be empty, but got >{:?}<. \
            Input expression content for parse_expr: {:?} \
            Line number: {}",
            parse_result.tokens.len(),
            remaining,
            expr_content_str,
            base_line_number
        );
    }

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