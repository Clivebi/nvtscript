if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108316" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-01-12 08:57:15 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetWare Core Protocol (NCP) Detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 524 );
	script_tag( name: "summary", value: "The script checks the presence of a service supporting the
  NetWare Core Protocol (NCP)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = unknownservice_get_port( default: 524 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x44, 0x6d, 0x64, 0x54, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x00, 0xff, 0x01, 0xff, 0x04 );
send( socket: soc, data: req );
res = recv( socket: soc, length: 64 );
close( soc );
if(res && IsMatchRegexp( hexstr( res ), "^744E635000000010333300" )){
	set_kb_item( name: "netware/ncp/" + port + "/detected", value: TRUE );
	set_kb_item( name: "netware/ncp/detected", value: TRUE );
	service_register( port: port, proto: "ncp", message: "A service supporting the NetWare Core Protocol is running at this port." );
	log_message( port: port, data: "A service supporting the NetWare Core Protocol is running at this port." );
}
exit( 0 );

