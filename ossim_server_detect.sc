if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.9000001" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2008-08-21 14:43:25 +0200 (Thu, 21 Aug 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "OSSIM Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "find_service1.sc" );
	script_require_ports( "Services/unknown", 40001 );
	script_xref( name: "URL", value: "http://www.ossim.net" );
	script_tag( name: "solution", value: "If possible, filter incoming connections to the service so that it is
  used by trusted sources only." );
	script_tag( name: "summary", value: "A OSSIM server is listening on the remote system.

  Description :

  The remote system is running an OSSIM server. OSSIM (Open Source
  Security Information Management) is a centralized security management
  information system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 40001 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
rand = rand() % 10;
data = "connect id=\"" + rand + "\" type=\"sensor\"\n";
send( socket: soc, data: data );
recv = recv( socket: soc, length: 64 );
close( soc );
if(recv == "ok id=\"" + rand + "\"\n"){
	log_message( port: port );
	service_register( port: port, ipproto: "tcp", proto: "ossim_server" );
}
exit( 0 );

