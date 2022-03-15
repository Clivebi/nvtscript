if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146114" );
	script_version( "2021-06-11T10:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 10:00:57 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-11 08:29:02 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Lucee Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Lucee." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.lucee.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res1 = http_get_cache( port: port, item: "/" );
res2 = http_get_cache( port: port, item: "/lucee/admin/server.cfm" );
res3 = http_get_cache( port: port, item: "/lucee/templates/error/error.cfm" );
res4 = http_get_cache( port: port, item: "/lucee/doc/index.cfm" );
if(ContainsString( res1, "You are now successfully running Lucee" ) || IsMatchRegexp( res1, "X-Lucee-Version|X-CB-Server: LUCEE|X-IDG-Appserver: Lucee" ) || ( ContainsString( res2, "<title>Lucee Server Administrator" ) && ContainsString( res2, "LuceeForms" ) ) || ContainsString( res3, "lucee-err" ) || ContainsString( res4, "<title>Lucee documentation" )){
	version = "unknown";
	install = "/";
	set_kb_item( name: "lucee/detected", value: TRUE );
	set_kb_item( name: "lucee/http/detected", value: TRUE );
	vers = eregmatch( pattern: "X-Lucee-Version: ([0-9.]+)", string: res1 );
	if( !isnull( vers[3] ) ){
		version = vers[3];
		concUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	}
	else {
		vers = eregmatch( pattern: "Lucee ([0-9.]+) on your system", string: res1 );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
		}
		else {
			vers = eregmatch( pattern: "Lucee ([0-9.]+) Error", string: res3 );
			if(!isnull( vers[1] )){
				version = vers[1];
				concUrl = http_report_vuln_url( port: port, url: "/lucee/templates/error/error.cfm", url_only: TRUE );
			}
		}
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:lucee:lucee_server:" );
	if(!cpe){
		cpe = "cpe:/a:lucee:lucee_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Lucee", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

