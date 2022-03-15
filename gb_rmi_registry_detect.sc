if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105839" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-08-01 09:40:35 +0200 (Mon, 01 Aug 2016)" );
	script_name( "RMI-Registry Detection" );
	script_tag( name: "summary", value: "This Script detects the RMI-Registry Service" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 1099 );
	exit( 0 );
}
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 1099 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "JRMI" + raw_string( 0x00, 0x02, 0x4b );
send( socket: soc, data: req );
res = recv( socket: soc, length: 128, min: 7 );
close( soc );
if(hexstr( res[0] ) != "4e" || ( getword( blob: res, pos: 1 ) + 7 ) != strlen( res )){
	exit( 0 );
}
service_register( port: port, proto: "rmi_registry" );
log_message( port: port, data: "The RMI-Registry Service is running at this port" );
exit( 0 );

