if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105065" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-07-18 18:29:45 +0200 (Fri, 18 Jul 2014)" );
	script_name( "Apache Cassandra Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "nessus_detect.sc" );
	script_require_ports( "Services/unknown", 9160 );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = unknownservice_get_port( default: 9160 );
if(get_kb_item( "generic_echo_test/" + port + "/failed" )){
	exit( 0 );
}
if(!get_kb_item( "generic_echo_test/" + port + "/tested" )){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: NASLString( "TestThis\\r\\n" ) );
	r = recv_line( socket: soc, length: 10 );
	close( soc );
	if(ContainsString( r, "TestThis" )){
		set_kb_item( name: "generic_echo_test/" + port + "/failed", value: TRUE );
		exit( 0 );
	}
}
set_kb_item( name: "generic_echo_test/" + port + "/tested", value: TRUE );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
cmd = "execute_cql3_query";
cmd_len = strlen( cmd ) % 256;
sql = "select release_version from system.local;";
sql_len = strlen( sql ) % 256;
req = raw_string( 0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, cmd_len ) + cmd + raw_string( 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, sql_len ) + sql + raw_string( 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00 );
alen = strlen( req ) % 256;
req = raw_string( 0x00, 0x00, 0x00, alen ) + req;
send( socket: soc, data: req );
recv = recv( socket: soc, length: 4096 );
close( soc );
if(!recv || !ContainsString( recv, "execute_cql3_query" )){
	exit( 0 );
}
vers = "unknown";
install = port + "/tcp";
for(i = 0;i < strlen( recv );i++){
	if(recv[i] == "\x00"){
		ret += " ";
	}
	if(isprint( c: recv[i] )){
		ret += recv[i];
	}
}
version = eregmatch( pattern: "release_version\\s*([0-9.]+)", string: ret );
if(!isnull( version[1] )){
	vers = version[1];
}
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:apache:cassandra:" );
if(!cpe){
	cpe = "cpe:/a:apache:cassandra";
}
set_kb_item( name: "apache/cassandra/detected", value: TRUE );
service_register( port: port, proto: "cassandra" );
register_product( cpe: cpe, location: install, port: port );
log_message( data: build_detection_report( app: "Apache Cassandra", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port, expert_info: "Request:\n" + hexdump( ddata: req ) + "\nResponse:\n" + hexdump( ddata: recv ) );
exit( 0 );

