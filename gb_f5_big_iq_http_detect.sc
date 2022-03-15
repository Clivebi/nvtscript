if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105165" );
	script_version( "2021-05-27T10:41:06+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-27 10:41:06 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2015-01-12 14:37:50 +0100 (Mon, 12 Jan 2015)" );
	script_name( "F5 Networks BIG-IQ Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of F5 Networks BIG-IQ." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/ui/login/";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>BIG-IQ" ) || !ContainsString( buf, "F5 Networks" )){
	exit( 0 );
}
_version = "unknown";
_build = "unknown";
set_kb_item( name: "f5/big_iq/detected", value: TRUE );
set_kb_item( name: "f5/big_iq/http/detected", value: TRUE );
set_kb_item( name: "f5/big_iq/http/port", value: port );
vers = eregmatch( pattern: "\\?ver=([0-9.]+)", string: buf );
if( !isnull( vers[1] ) ){
	version = vers[1];
	_vers = split( buffer: version, sep: ".", keep: FALSE );
	_version = _vers[0] + "." + _vers[1] + "." + _vers[2];
	_build = version - ( _version + "." );
	set_kb_item( name: "f5/big_iq/http/" + port + "/concluded", value: vers[0] );
	set_kb_item( name: "f5/big_iq/http/" + port + "/concUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
}
else {
	url = "/ui/js/templates.js";
	req = http_get( port: port, item: url );
	buf = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "Management&version=([0-9.]+)", string: buf );
	if(!isnull( vers[1] )){
		_version = vers[1];
		set_kb_item( name: "f5/big_iq/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "f5/big_iq/http/" + port + "/concUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
}
set_kb_item( name: "f5/big_iq/http/" + port + "/version", value: _version );
set_kb_item( name: "f5/big_iq/http/" + port + "/build", value: _build );
exit( 0 );

