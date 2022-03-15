if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143507" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-02-12 06:40:55 +0000 (Wed, 12 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Java Debug Wire Protocol (JDWP) Service Detection" );
	script_tag( name: "summary", value: "A Java Debug Wire Protocol (JDWP) service is running at this host.

  The Java Debug Wire Protocol (JDWP) is the protocol used for communication between a debugger and the Java
  virtual machine (VM) which it debugs." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service1.sc", "find_service2.sc", "find_service3.sc", "find_service4.sc", "find_service5.sc", "find_service6.sc", "nessus_detect.sc" );
	script_require_ports( "Services/jdwp", 8000 );
	exit( 0 );
}
require("dump.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = service_get_port( default: 8000, proto: "jdwp" );
if(get_kb_item( "generic_echo_test/" + port + "/failed" )){
	exit( 0 );
}
if(!get_kb_item( "generic_echo_test/" + port + "/tested" )){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: "TestThis\\r\\n" );
	r = recv_line( socket: soc, length: 10 );
	close( soc );
	if(ContainsString( r, "TestThis" )){
		set_kb_item( name: "generic_echo_test/" + port + "/failed", value: TRUE );
		exit( 0 );
	}
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
msg = "JDWP-Handshake";
send( socket: soc, data: msg );
recv = recv( socket: soc, length: 512 );
if(recv != msg){
	close( soc );
	exit( 0 );
}
set_kb_item( name: "jdwp/detected", value: TRUE );
service_register( port: port, proto: "jdwp" );
data = raw_string( 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01 );
send( socket: soc, data: data );
recv = recv( socket: soc, length: 1024 );
close( soc );
if(recv && strlen( recv ) > 16){
	recv = substr( recv, 15 );
	recv = bin2string( ddata: recv, noprint_replacement: " " );
	info = recv;
}
report = "A Java Debug Wired Protocol (JDWP) service is running at this port.";
if(info){
	report += "\n\nThe following information could be extracted:\n\n" + info;
}
log_message( port: port, data: report );
exit( 0 );

