if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103841" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-11-29 14:30:41 +0100 (Fri, 29 Nov 2013)" );
	script_name( "Greenbone Security Assistant (GSA) Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 9392 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  determine if it is a GSA from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 9392 );
url = "/login/login.html";
buf = http_get_cache( item: url, port: port );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<form action=\"/omp\" method=\"" ) && ContainsString( buf, "Greenbone Security Assistant" )){
	install = "/";
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "<span class=\"version\">Version ([^<]+)</span>", icase: FALSE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "greenbone_security_assistant/detected", value: TRUE );
	set_kb_item( name: "greenbone_security_assistant/pre80/detected", value: TRUE );
	set_kb_item( name: "greenbone_security_assistant/" + port + "/omp", value: TRUE );
	set_kb_item( name: "greenbone_security_assistant/" + port + "/version", value: vers );
	set_kb_item( name: "openvas_gvm/framework_component/detected", value: TRUE );
	replace_kb_item( name: "www/" + port + "/can_host_php", value: "no" );
	replace_kb_item( name: "www/" + port + "/can_host_asp", value: "no" );
	cpe = build_cpe( value: vers, exp: "^([0-9.-]+)", base: "cpe:/a:greenbone:greenbone_security_assistant:" );
	if(!cpe){
		cpe = "cpe:/a:greenbone:greenbone_security_assistant";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", port: port, desc: "Greenbone Security Assistant (GSA) Detection", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Greenbone Security Assistant", version: vers, concluded: version[0], install: install, cpe: cpe ), port: port );
	exit( 0 );
}
url = "/login";
buf = http_get_cache( item: url, port: port );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Greenbone Security Assistant</title>" ) || ContainsString( buf, "<title>Greenbone Security Manager</title>" ) )){
	install = "/";
	vers = "unknown";
	set_kb_item( name: "greenbone_security_assistant/detected", value: TRUE );
	set_kb_item( name: "greenbone_security_assistant/80plus/detected", value: TRUE );
	set_kb_item( name: "greenbone_security_assistant/" + port + "/gmp", value: TRUE );
	set_kb_item( name: "greenbone_security_assistant/" + port + "/version", value: vers );
	set_kb_item( name: "openvas_gvm/framework_component/detected", value: TRUE );
	replace_kb_item( name: "www/" + port + "/can_host_php", value: FALSE );
	replace_kb_item( name: "www/" + port + "/can_host_asp", value: FALSE );
	cpe = build_cpe( value: vers, exp: "^([0-9.-]+)", base: "cpe:/a:greenbone:greenbone_security_assistant:" );
	if(!cpe){
		cpe = "cpe:/a:greenbone:greenbone_security_assistant";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", port: port, desc: "Greenbone Security Assistant (GSA) Detection", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Greenbone Security Assistant", version: vers, install: install, cpe: cpe ), port: port );
}
exit( 0 );

