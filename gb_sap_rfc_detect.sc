if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141120" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-30 08:06:33 +0700 (Wed, 30 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SAP RFC Interface Detection" );
	script_tag( name: "summary", value: "Detection of SAP RFC Interface.

The RFC (Remote Function Call) interface enables function calls between two SAP systems, or between an SAP system
and an external system." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://archive.sap.com/documents/docs/DOC-60424" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
url = "/sap/bc/soap/rfc";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Logon failed" ) && ContainsString( res, "sap-system" )){
	set_kb_item( name: "sap_rfc/detected", value: TRUE );
	set_kb_item( name: "sap_rfc/port", value: port );
	report = "SAP RFC Interface is enabled at the following URL:  " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

