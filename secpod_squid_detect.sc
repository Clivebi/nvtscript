if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900611" );
	script_version( "2021-09-03T08:53:57+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:53:57 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)" );
	script_name( "Squid Proxy Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "proxy_use.sc", "global_settings.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of squid.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = get_kb_item( "Services/http_proxy" );
if(!port){
	port = 3128;
}
if(!get_port_state( port )){
	port = 8080;
}
if(!get_port_state( port )){
	exit( 0 );
}
req = http_get( item: "http://www.$$$$$", port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
banner = http_get_remote_headers( port: port );
pattern = "^Server: squid";
if( data = egrep( pattern: pattern, string: res, icase: TRUE ) ){
	installed = TRUE;
}
else {
	if(data = egrep( pattern: pattern, string: banner, icase: TRUE )){
		installed = TRUE;
	}
}
if(installed){
	concl = chomp( data );
	vers = "unknown";
	install = port + "/tcp";
	version = eregmatch( pattern: "^Server: squid/([0-9a-zA-Z.]+)", string: data, icase: TRUE );
	if(version[1]){
		vers = version[1];
		set_kb_item( name: "www/" + port + "/Squid", value: vers );
		concl = version[0];
	}
	set_kb_item( name: "squid_proxy_server/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+.[a-zA-Z0-9]+)", base: "cpe:/a:squid-cache:squid:" );
	if(!cpe){
		cpe = "cpe:/a:squid-cache:squid";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Squid Proxy Server", version: vers, install: install, cpe: cpe, concluded: concl ), port: port );
}
exit( 0 );

