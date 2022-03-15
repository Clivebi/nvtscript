if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113759" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check for ident Service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/auth", 113 );
	script_tag( name: "summary", value: "The remote host is running an ident daemon.

  The Ident Protocol is designed to work as a server daemon, on a user's
  computer, where it receives requests to a specified port, generally 113. The
  server will then send a specially designed response that identifies the
  username of the current user." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( proto: "auth", default: 113 );
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
data = strcat( port, ",", get_source_port( soc ) );
send( socket: soc, data: NASLString( data, "\\r\\n" ) );
buf = recv_line( socket: soc, length: 1024 );
close( soc );
if(ContainsString( buf, "ERROR" ) || ContainsString( buf, data ) || ContainsString( buf, "USERID" )){
	service_register( port: port, proto: "auth" );
	set_kb_item( name: "ident/detected", value: TRUE );
	set_kb_item( name: "ident/port", value: port );
}
exit( 0 );

