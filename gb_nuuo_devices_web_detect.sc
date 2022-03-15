if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105855" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-08 18:28:02 +0200 (Mon, 08 Aug 2016)" );
	script_name( "NUUO Device Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of NUUO devices" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( port: port, item: "/" );
if(!IsMatchRegexp( buf, "<title>(NUUO )?Network Video Recorder Login</title>" ) && !ContainsString( buf, "var VENDOR_NAME \"NUUO\"" )){
	exit( 0 );
}
set_kb_item( name: "nuuo/web/detected", value: TRUE );
co = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: buf );
if(!isnull( co[1] )){
	set_kb_item( name: "nuuo/web/cookie", value: co[1] );
}
version = eregmatch( pattern: "js\\?v=([0-9.]+)", string: buf );
vers = "unknown";
cpe = "cpe:/a:nuuo:nuuo";
if(!isnull( version[1] )){
	_v = split( buffer: version[1], sep: ".", keep: TRUE );
	for v in _v {
		v = ereg_replace( string: v, pattern: "^0+([0-9]+)", replace: "\\1" );
		_vers += v;
	}
}
if( _vers ){
	vers = _vers;
	cpe += ":" + vers;
}
else {
	url = "/upgrade_handle.php?cmd=getcurrentinfo";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	version = eregmatch( pattern: "<Titan>([0-9.]+)", string: res );
	if(!isnull( version[1] )){
		_v = split( buffer: version[1], sep: ".", keep: TRUE );
		for v in _v {
			v = ereg_replace( string: v, pattern: "^0+([0-9]+)", replace: "\\1" );
			_vers += v;
		}
		vers = _vers;
		concUrl = url;
		cpe += ":" + vers;
	}
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "NUUO Network Video Recorder", version: vers, install: "/", cpe: cpe, concluded: version[0], concludedUrl: concUrl ), port: port );
exit( 0 );

