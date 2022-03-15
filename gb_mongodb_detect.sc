if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100747" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-08-06 15:09:20 +0200 (Fri, 06 Aug 2010)" );
	script_name( "MongoDB Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/www", "Services/mongodb", "Services/unknown", 27017 );
	script_xref( name: "URL", value: "https://www.mongodb.com/" );
	script_tag( name: "summary", value: "Detects the installed version of
  MongoDB database.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("dump.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
ports = make_list();
unkwn_ports = unknownservice_get_ports( default_port_list: make_list( 27017 ) );
if(unkwn_ports){
	ports = make_list( ports,
		 unkwn_ports );
}
http_ports = http_get_ports( default_port_list: make_list( 27017 ) );
if(http_ports){
	for http_port in http_ports {
		banners = get_kb_list( "FindService/tcp/" + http_port + "/get_http" );
		if(!banners){
			continue;
		}
		for banner in banners {
			if(!banner || !IsMatchRegexp( banner, "It looks like you are trying to access MongoDB over HTTP on the native driver port" )){
				continue;
			}
			ports = make_list( ports,
				 http_ports );
		}
	}
}
mongo_ports = service_get_ports( default_port_list: make_list( 27017 ), proto: "mongodb" );
if(mongo_ports){
	ports = make_list( ports,
		 mongo_ports );
}
ports = nasl_make_list_unique( ports );
req1 = raw_string( 0x3c, 0x00, 0x00, 0x00, 0xff, 0x0d, 0xc2, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x10, 0x77, 0x68, 0x61, 0x74, 0x73, 0x6d, 0x79, 0x75, 0x72, 0x69, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 );
req2 = raw_string( 0x3f, 0x00, 0x00, 0x00, 0x00, 0x0e, 0xc2, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x18, 0x00, 0x00, 0x00, 0x01, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00 );
for port in ports {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	send( socket: soc, data: req1 );
	buf = recv( socket: soc, length: 1024 );
	if(!buf || !ContainsString( buf, "you" ) || !ContainsString( buf, "ok" ) || !ContainsString( hexstr( buf ), "ff0dc2c0" )){
		close( soc );
		continue;
	}
	service_register( port: port, proto: "mongodb" );
	vers = "unknown";
	send( socket: soc, data: req2 );
	buf = recv( socket: soc, length: 1024 );
	close( soc );
	if(buf){
		txt = bin2string( ddata: buf );
		version = eregmatch( pattern: "version([0-9.]+)(-)?(rc([0-9]))?", string: txt );
		if( version[3] && version[1] ){
			vers = version[1] + "-" + version[3];
		}
		else {
			if(version[1] && !( version[3] )){
				vers = version[1];
			}
		}
	}
	set_kb_item( name: "mongodb/installed", value: TRUE );
	set_kb_item( name: "mongodb/" + port + "/version", value: vers );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+-?[a-zA-Z0-9]+?)", base: "cpe:/a:mongodb:mongodb:" );
	if(!cpe){
		cpe = "cpe:/a:mongodb:mongodb";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "mongodb" );
	log_message( data: build_detection_report( app: "MongoDB", version: vers, install: port + "/tcp", cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

