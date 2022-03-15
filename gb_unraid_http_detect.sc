if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143516" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-02-14 05:45:30 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Unraid OS Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Unraid OS.

  The script sends a connection request to the server and attempts to detect Unraid OS and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://unraid.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/login" );
if(IsMatchRegexp( res, "unraid" ) && ContainsString( res, "/webGui/images/" ) && ( ContainsString( res, "placeholder=\"Username\"" ) || ContainsString( res, "unRAIDServer.plg" ) )){
	version = "unknown";
	url = "/Main";
	res = http_get_cache( port: port, item: url );
	vers = eregmatch( pattern: "Version.*([0-9]+\\.[0-9]+\\.[0-9]+)&nbsp;<a href='#' title='View Release Notes'", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	url = "/Settings";
	if(http_vuln_check( port: port, url: url, pattern: "\"PanelText\">Date and Time", extra_check: "\"PanelText\">Disk Settings", check_header: TRUE )){
		set_kb_item( name: "unraid/http/" + port + "/noauth", value: TRUE );
		set_kb_item( name: "unraid/http/" + port + "/noauth/checkedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	set_kb_item( name: "unraid/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:unraid:unraid:" );
	if(!cpe){
		cpe = "cpe:/o:unraid:unraid";
	}
	os_register_and_report( os: "Unraid OS", cpe: cpe, desc: "Unraid OS Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Unraid", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

