if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802137" );
	script_version( "2021-04-14T09:28:27+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 09:28:27 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nfs-utils rpc.rquotad Service Detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "RPC" );
	script_dependencies( "secpod_rpc_portmap_udp.sc", "secpod_rpc_portmap_tcp.sc" );
	script_mandatory_keys( "rpc/portmap" );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0625" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/265" );
	script_xref( name: "URL", value: "http://www.exploitsearch.net/index.php?q=CVE-1999-0625" );
	script_xref( name: "URL", value: "http://www.iss.net/security_center/reference/vuln/rquotad.htm" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute to gain
  information about NFS services including user/system quotas." );
	script_tag( name: "insight", value: "The flaw is due to error in the 'rpc.rquotad' service. If this
  service is running then disable it as it may become a security threat." );
	script_tag( name: "summary", value: "This script detects the running 'rpc.rquotad' service on the host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("rpc.inc.sc");
require("byte_func.inc.sc");
RPC_PROG = 100011;
port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_UDP );
if(port){
	security_message( port: port, proto: "udp" );
}
port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_TCP );
if(port){
	security_message( port: port, proto: "tcp" );
}
exit( 0 );

