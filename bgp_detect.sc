if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11907" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "BGP (Border Gateway Protocol) Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 179 );
	script_tag( name: "solution", value: "If the remote service is not used, disable it.
  Make sure that access to this service is either filtered so that only
  allowed hosts can connect to it, or that TCP MD5 is enabled to protect
  this service from rogue connections." );
	script_tag( name: "summary", value: "The remote host is running a BGP (Border Gateway Protocol) service.

  Description :

  The remote host is running BGP, a popular routing protocol. This indicates
  that the remote host is probably a network router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = 179;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = this_host();
v = eregmatch( pattern: "^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9])+$", string: s );
if(isnull( v )){
	exit( 0 );
}
for(i = 1;i <= 4;i++){
	a[i] = int( v[i] );
}
r = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
r += raw_string( 0, 45, 1, 4, rand() % 256, rand() % 256, 0, 180, a[1], a[2], a[3], a[4], 0, 2, 6, 1, 4, 0, 1, 0, 1, 2, 2, 80, 0, 2, 2, 2, 0 );
send( socket: soc, data: r );
r = recv( socket: soc, length: 16, min: 16 );
if(strlen( r ) < 16){
	exit( 0 );
}
for(i = 0;i < 16;i++){
	if(ord( r[i] ) != 0xFF){
		break;
	}
}
if(i < 16){
	exit( 0 );
}
r = recv( socket: soc, length: 2, min: 2 );
len = ord( r[0] ) * 256 + ord( r[1] );
len -= 18;
if(len <= 0){
	exit( 0 );
}
r = recv( socket: soc, length: len, min: len );
type = ord( r[0] );
if(type == 1){
	ver = ord( r[1] );
	as = 256 * ord( r[2] ) + ord( r[3] );
	ht = 256 * ord( r[4] ) + ord( r[5] );
}
service_register( port: port, proto: "bgp" );
log_message( port );

