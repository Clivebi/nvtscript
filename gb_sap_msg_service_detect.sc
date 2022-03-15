if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141067" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-05-09 09:04:58 +0700 (Wed, 09 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SAP Message Server Service Detection" );
	script_tag( name: "summary", value: "A SAP Message Server Service is running at this host.

SAP Message Server is for

  - Central communication channel between the individual application servers (instances) of the system

  - Load distribution of logons using SAP GUI and RFC with logon groups

  - Information point for the Web Dispatcher and the application servers" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 3600, 3900 );
	script_xref( name: "URL", value: "https://www.sap.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = unknownservice_get_port( default: 3900 );
if(port < 3600 || port >= 3700){
	if(port < 3900 || port >= 4000){
		exit( 0 );
	}
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
client = "-" + crap( data: " ", length: 39 );
query = raw_string( 0x00, 0x00, 0x00, 0x6e, "**MESSAGE**", 0x00, 0x04, 0x00, client, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, client, 0x00, 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
if(!recv || strlen( recv ) < 111 || substr( recv, 4, 14 ) != "**MESSAGE**"){
	close( soc );
	exit( 0 );
}
set_kb_item( name: "sap_message_server/detected", value: TRUE );
service_register( port: port, ipproto: "tcp", proto: "sap_msg_service" );
server = substr( recv, 72, 111 );
server_name = bin2string( ddata: server, noprint_replacement: "" );
query = raw_string( 0x00, 0x00, 0x00, 0xa2, "**MESSAGE**", 0x00, 0x04, 0x00, server, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, client, 0x00, 0x00, 0x1e, 0x00, 0x01, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 2048 );
close( soc );
if(recv && strlen( recv ) > 119){
	info = substr( recv, 119 );
}
report = "A SAP Message Server service is running at this port.\n\nThe following server name was extracted:\n\n" + "Server Name:     " + server_name + "\n";
if(info){
	report += "\nAdditional obtained info:\n\n" + info;
}
log_message( port: port, data: report );
exit( 0 );

