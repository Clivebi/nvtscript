if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807894" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-05 16:18:47 +0530 (Wed, 05 Oct 2016)" );
	script_name( "Serimux SSH Console Switch Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Serimux SSH Console Switch.

  This script sends an HTTP GET request and tries to ensure the presence of
  Serimux SSH Console Switch." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
serPort = http_get_port( default: 80 );
if(!http_can_host_asp( port: serPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cgi_dir", http_cgi_dirs( port: serPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/nti/login.asp", port: serPort );
	rcvRes = http_send_recv( port: serPort, data: sndReq );
	if(ContainsString( rcvRes, ">SERIMUX-S-x Console Switch" ) && ContainsString( rcvRes, ">Welcome, please log in" )){
		version = "unknown";
		set_kb_item( name: "Serimux/Console/Switch/Installed", value: TRUE );
		cpe = "cpe:/a:serimux:serimux_console_switch";
		register_product( cpe: cpe, location: install, port: serPort, service: "www" );
		log_message( data: build_detection_report( app: "Serimux SSH Console Switch", version: version, install: install, cpe: cpe, concluded: version ), port: serPort );
		exit( 0 );
	}
}
exit( 0 );

