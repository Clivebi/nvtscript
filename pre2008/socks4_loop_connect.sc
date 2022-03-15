if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17155" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "Connect back to SOCKS4 server" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "socks.sc" );
	script_require_ports( "Services/socks4", 1080 );
	script_mandatory_keys( "socks4/detected" );
	script_tag( name: "summary", value: "It was possible to connect to the SOCKS4 server
  through itself." );
	script_tag( name: "impact", value: "This allow anybody to saturate the proxy CPU, memory or
  file descriptors." );
	script_tag( name: "solution", value: "Reconfigure your proxy so that it refuses connections to itself" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1080, proto: "socks4" );
s = open_sock_tcp( port );
if(!s){
	exit( 0 );
}
p2 = port % 256;
p1 = port / 256;
a = split( buffer: get_host_ip(), sep: "." );
cmd = raw_string( 4, 1, p1, p2, int( a[0] ), int( a[1] ), int( a[2] ), int( a[3] ) ) + "root" + "\0";
for(i = 3;i >= 0;i--){
	send( socket: s, data: cmd );
	data = recv( socket: s, length: 8, min: 8 );
	if(strlen( data ) != 8 || ord( data[0] ) != 4 || ord( data[1] ) != 90){
		break;
	}
}
close( s );
if(i < 0){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

