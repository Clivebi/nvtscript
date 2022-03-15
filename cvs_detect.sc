if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10051" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "A CVS pserver is running" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/cvspserver" );
	script_tag( name: "summary", value: "A CVS (Concurrent Versions System) server is installed, and it is configured
  to have its own password file, or use that of the system. This service starts as a daemon, listening on port
  TCP:port." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 2401, proto: "cvspserver" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
senddata = NASLString( "\\r\\n\\r\\n" );
send( socket: soc, data: senddata );
recvdata = recv_line( socket: soc, length: 1000 );
close( soc );
if(recvdata && ContainsString( recvdata, "cvs" )){
	report = "A CVS server was detected on the target system.";
	log_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

