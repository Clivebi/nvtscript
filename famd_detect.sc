if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18186" );
	script_version( "2021-09-28T10:33:08+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 10:33:08 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "File Alteration Monitor daemon (famd) Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_require_ports( "Services/unknown" );
	script_dependencies( "find_service2.sc" );
	script_tag( name: "summary", value: "The File Alteration Monitor daemon is running on this port." );
	script_tag( name: "insight", value: "This service does not need to be reachable from the outside, it
  is therefore recommended that reconfigure it to disable network access." );
	script_tag( name: "solution", value: "Start famd with the -L option or edit /etc/fam.conf and set the
  option 'local_only' to 'true' and restartd the famd service.

  Alternatively, you may wish to filter incoming traffic to this port." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("network_func.inc.sc");
a = get_host_ip();
local = ( IsMatchRegexp( a, "^0*127\\.[0-9]+\\.[0-9]+\\.[0-9]+$" ) );
lan = local || is_private_addr( addr: a );
port = unknownservice_get_port( nodefault: TRUE );
s = open_sock_tcp( port );
if(!s){
	exit( 0 );
}
send( socket: s, data: "\0\0\0\x1aN0 500 500 sockmeister\00\x0a\0" );
b = recv( socket: s, length: 512 );
close( s );
if(isnull( b ) || substr( b, 0, 2 ) != "\0\0\0"){
	exit( 0 );
}
l = strlen( b );
if(l < 5){
	exit( 0 );
}
if(b[l - 1] != "\0" || ord( b[3] ) != l - 4 || ord( b[4] ) != "/"){
	exit( 0 );
}
service_register( port: port, ipproto: "tcp", proto: "famd" );
r = "The File Alteration Monitor daemon is running on this port\n";
if( local ) {
	log_message( port: port, data: r + ".\n" );
}
else {
	r += " and does not need to be reachable from the outside.\n";
	if(!lan){
		r += "Exposing it on Internet is definitely not a good idea.\n";
	}
	r += "\nSolution : to restrict it to the loopback interface,
run it with -L or set \"local_only = false\" in /etc/fam.conf";
	log_message( port: port, data: r );
	exit( 0 );
}
exit( 0 );

