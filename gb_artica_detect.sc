if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100870" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Artica Proxy Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Artica Proxy." );
	script_xref( name: "URL", value: "http://artica-proxy.com/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9000 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/fw.login.php";
buf = http_get_cache( port: port, item: url );
if( !ContainsString( buf, "artica-language" ) ){
	url = "/logon.php";
	buf = http_get_cache( item: url, port: port );
	if(!ContainsString( buf, "artica_username" ) || !ContainsString( buf, "artica_password" )){
		exit( 0 );
	}
	concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
else {
	concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
version = "unknown";
set_kb_item( name: "artica/proxy/detected", value: TRUE );
vers = eregmatch( pattern: "Artica[:]? ([0-9.]+)", string: buf );
if(!isnull( vers[1] )){
	version = vers[1];
}
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:articatech:artica_proxy:" );
if(!cpe){
	cpe = "cpe:/a:articatech:artica_proxy";
}
os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Artica Proxy Detection (HTTP)", runs_key: "unixoide" );
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Artica Proxy", version: version, install: "/", cpe: cpe, concludedUrl: concl_url, concluded: vers[0] ), port: port );
exit( 0 );

