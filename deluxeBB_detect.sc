if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100063" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-20 11:01:53 +0100 (Fri, 20 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "deluxeBB Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running deluxeBB a widely installed Open Source forum
solution." );
	script_xref( name: "URL", value: "http://www.deluxebb.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/board", "/forum", "/deluxebb", "/forums", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(( egrep( pattern: "^Set-Cookie: lastvisita.*", string: buf ) && egrep( pattern: ".*DeluxeBB.*", string: buf ) ) || egrep( pattern: "DeluxeBB .*</a> is copyrighted to the DeluxeBB.*", string: buf ) || egrep( pattern: ".*powered by DeluxeBB.*", string: buf )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: ">DeluxeBB ([0-9]+\\.+[0-9.]*)</a> is copyrighted.*" );
		if(!isnull( version[1] )){
			vers = version[1];
		}
		set_kb_item( name: "deluxebb/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:deluxebb:deluxebb:" );
		if(!cpe){
			cpe = "cpe:/a:deluxebb:deluxebb";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "DeluxeBB", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

