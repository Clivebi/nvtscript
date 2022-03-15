if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808659" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)" );
	script_name( "Honeywell IP-Camera Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Honeywell IP-Cameras.

  This script sends an HTTP GET request and tries to ensure the presence of
  Honeywell IP-Cameras." );
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
achPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/cgi-bin", http_cgi_dirs( port: achPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/chksession.cgi", port: achPort );
	rcvRes = http_send_recv( port: achPort, data: sndReq );
	if(ContainsString( rcvRes, "<title>Honeywell IP-Camera login</title>" ) && ContainsString( rcvRes, "password" )){
		version = "unknown";
		set_kb_item( name: "Honeywell/IP_Camera/Installed", value: TRUE );
		cpe = "cpe:/a:honeywell:honeywell_ip_camera";
		register_product( cpe: cpe, location: install, port: achPort, service: "www" );
		log_message( data: build_detection_report( app: "Honeywell IP-Camera", version: version, install: install, cpe: cpe, concluded: version ), port: achPort );
	}
}
exit( 0 );

