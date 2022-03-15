if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103081" );
	script_version( "2021-09-29T12:11:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 12:11:02 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-21 13:57:38 +0100 (Mon, 21 Feb 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "F-Secure Internet Gatekeeper Detection (HTTP)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9012 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of F-Secure Internet Gatekeeper." );
	script_xref( name: "URL", value: "https://www.f-secure.com/en/business/downloads/internet-gatekeeper" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9012 );
url = "/";
res = http_get_cache( port: port, item: url );
if(!ContainsString( res, "<TITLE>F-Secure Internet Gatekeeper</TITLE>" ) && !ContainsString( res, "fswebui.css" )){
	url = "/login.jsf";
	res = http_get_cache( item: url, port: port );
	if(!ContainsString( res, "<title>F-Secure Anti-Virus Gateway for Linux</title>" )){
		exit( 0 );
	}
}
version = "unknown";
install = "/";
concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
set_kb_item( name: "fsecure/internet_gatekeeper/detected", value: TRUE );
set_kb_item( name: "fsecure/internet_gatekeeper/http/detected", value: TRUE );
url = "/login";
res = http_get_cache( port: port, item: url );
vers = eregmatch( pattern: "/igk/([0-9.]+)/", string: res );
if(!isnull( vers[1] )){
	version = vers[1];
	concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, desc: "F-Secure Internet Gatekeeper Detection (HTTP)", runs_key: "unixoide" );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:f-secure:internet_gatekeeper:" );
if(!cpe){
	cpe = "cpe:/a:f-secure:internet_gatekeeper";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "F-Secure Internet Gatekeeper", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
exit( 0 );

