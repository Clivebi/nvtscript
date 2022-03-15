if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901206" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "RPC rstatd Service Detection (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Useless services" );
	script_dependencies( "secpod_rpc_portmap_tcp.sc" );
	script_mandatory_keys( "rpc/portmap/tcp/detected" );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0624" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/115" );
	script_xref( name: "URL", value: "http://www.iss.net/security_center/advice/Services/SunRPC/rpc.rstatd/default.htm" );
	script_tag( name: "solution", value: "Disable the RPC rstatd service if not needed." );
	script_tag( name: "summary", value: "This remote host is running a RPC rstatd service via TCP." );
	script_tag( name: "insight", value: "The rstatd service is a RPC server which provides remotely monitorable statistics
  obtained from the kernel such as,

  - system uptime

  - cpu usage

  - disk usage

  - network usage

  - load averages

  - and more." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("rpc.inc.sc");
require("byte_func.inc.sc");
RPC_PROG = 100001;
port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_TCP );
if(!port){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
rpc_paket = rpc_construct_packet( program: RPC_PROG, prog_ver: 3, procedure: 1, data: NULL, udp: "tcp" );
send( socket: soc, data: rpc_paket );
res = recv( socket: soc, length: 4096 );
close( soc );
if(strlen( res ) < 100 || strlen( res ) > 150){
	exit( 0 );
}
pos = 20 + 4;
if(ord( res[pos] ) == 0 && ord( res[pos + 1] ) == 0 && ord( res[pos + 2] ) == 0 && ord( res[pos + 3] ) == 0){
	security_message( port: port );
}
exit( 0 );

