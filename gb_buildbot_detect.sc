if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800933" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Buildbot Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8010 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Buildbot." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8010 );
for dir in nasl_make_list_unique( "/", "/buildbot", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/about", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Buildbot" )){
		version = "unknown";
		ver = eregmatch( pattern: "Buildbot.?.?(([0-9.]+)([a-z][0-9]+)?)", string: rcvRes );
		if(!isnull( ver[2] )){
			if( !isnull( ver[3] ) ){
				version = ver[2] + "." + ver[3];
			}
			else {
				version = ver[2];
			}
		}
		set_kb_item( name: "Buildbot/Ver", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+\\.[0-9])([a-z][0-9]+)?", base: "cpe:/a:buildbot:buildbot:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:buildbot:buildbot";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Build bot", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

