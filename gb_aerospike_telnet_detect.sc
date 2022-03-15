if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140131" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-01-27 13:21:27 +0100 (Fri, 27 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Aerospike Database Detection (Telnet)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "summary", value: "Telnet based Detection of the Aerospike Database." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 3003 );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 3003 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
send( socket: soc, data: "version\n" );
recv = recv( socket: soc, length: 512 );
close( soc );
recv = chomp( recv );
if(!recv || !ContainsString( recv, "Aerospike" )){
	exit( 0 );
}
set_kb_item( name: "aerospike/detected", value: TRUE );
set_kb_item( name: "aerospike/telnet/port", value: port );
set_kb_item( name: "aerospike/telnet/" + port + "/concluded", value: recv );
version = "unknown";
edition = "Unknown Edition";
v = eregmatch( pattern: "build ([0-9.-]+)", string: recv );
if(!isnull( v[1] )){
	version = v[1];
}
if( ContainsString( recv, "Community Edition" ) ) {
	edition = "Community Edition";
}
else {
	if(ContainsString( recv, "Enterprise Edition" )){
		edition = "Enterprise Edition";
	}
}
service_register( port: port, proto: "aerospike_telnet" );
set_kb_item( name: "aerospike/edition", value: edition );
set_kb_item( name: "aerospike/xdr/" + port + "/version", value: version );
exit( 0 );

