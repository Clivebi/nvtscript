if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108082" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-02-10 13:00:00 +0100 (Fri, 10 Feb 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache JServ Protocol (AJP) v1.3 Detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 8009 );
	script_tag( name: "summary", value: "The script detects a service supporting the
  Apache JServ Protocol (AJP) version 1.3." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 8009 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x12, 0x34, 0x00, 0x01, 0x0a );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 10 );
close( soc );
if(strlen( buf ) != 5){
	exit( 0 );
}
if(IsMatchRegexp( hexstr( buf ), "^4142000109$" )){
	set_kb_item( name: "apache/ajp/detected", value: TRUE );
	set_kb_item( name: "apache/ajp/" + port + "/detected", value: TRUE );
	service_register( port: port, proto: "ajp13" );
	log_message( port: port, data: "A service supporting the Apache JServ Protocol (AJP) v1.3 seems to be running on this port." );
}
exit( 0 );

