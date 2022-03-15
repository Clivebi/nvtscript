if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100911" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "FreeNAS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of FreeNAS.

  The script sends a connection request to the server and attempts to detect FreeNAS and to extract its version." );
	script_xref( name: "URL", value: "http://freenas.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/ui/";
res = http_get_cache( port: port, item: url );
if(!ContainsString( res, "Etag: FreeNAS" )){
	url = "/legacy/account/login/";
	res = http_get_cache( port: port, item: url );
	if(!ContainsString( res, "Welcome to FreeNAS" )){
		url = "/account/login/";
		res = http_get_cache( port: port, item: url );
		if(!ContainsString( res, "title=\"FreeNAS" ) || !ContainsString( res, "title=\"iXsystems, Inc.\">" )){
			exit( 0 );
		}
	}
}
version = "unknown";
vers = eregmatch( pattern: "Etag: FreeNAS-([^\r\n]+)", string: res );
if(isnull( vers[1] )){
	vers = eregmatch( pattern: "iXsystems, Inc.</a> - ([^<\r\n]+)", string: res );
	if(isnull( vers[1] )){
		url = "/docs/intro.html";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: "<p>Version ([0-9.]+)", string: res );
	}
}
if(!isnull( vers[1] )){
	version = vers[1];
	version = str_replace( string: version, find: "-RELEASE", replace: "" );
	concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
set_kb_item( name: "freenas/detected", value: TRUE );
cpe = build_cpe( value: tolower( version ), exp: "^([0-9a-z.-]+)", base: "cpe:/a:freenas:freenas:" );
if(!cpe){
	cpe = "cpe:/a:freenas:freenas";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "FreeNAS", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
exit( 0 );

