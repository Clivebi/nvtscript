if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111015" );
	script_version( "2021-05-26T13:59:24+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-26 13:59:24 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2015-04-17 08:00:00 +0100 (Fri, 17 Apr 2015)" );
	script_name( "F5 FirePass Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of F5 FirePass." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "F5 FirePass Detection (HTTP)";
port = http_get_port( default: 80 );
req1 = http_get( item: NASLString( "/tunnel\\r\\n" ), port: port );
res1 = http_keepalive_send_recv( port: port, data: req1, bodyonly: FALSE );
url = "/admin/";
res2 = http_get_cache( item: url, port: port );
if(( res1 && ContainsString( res1, "FirePass server could not handle the request" ) ) || ( res2 && ContainsString( res2, "Version - FirePass" ) )){
	version = "unknown";
	set_kb_item( name: "f5/firepass/detected", value: TRUE );
	set_kb_item( name: "f5/firepass/http/detected", value: TRUE );
	ver = eregmatch( pattern: "Version - FirePass ([0-9.]+)", string: res2 );
	if(ver[1]){
		version = ver[1];
		conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/h:f5:firepass:" );
	if(!cpe){
		cpe = "cpe:/h:f5:firepass";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	if( version != "unknown" && version_in_range( version: version, test_version: "6.1.0", test_version2: "7.0.0" ) ) {
		os_register_and_report( os: "Slackware", version: "7.1", cpe: "cpe:/o:slackware:slackware_linux", port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	log_message( data: build_detection_report( app: "F5 FirePass", version: version, install: "/", cpe: cpe, concludedUrl: conclurl, concluded: ver[0] ), port: port );
}
exit( 0 );

