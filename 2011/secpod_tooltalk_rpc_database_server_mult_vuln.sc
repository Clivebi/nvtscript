if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902477" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-27 17:29:53 +0200 (Tue, 27 Sep 2011)" );
	script_cve_id( "CVE-2002-0677", "CVE-2002-0678" );
	script_bugtraq_id( 5083, 5082 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CDE ToolTalk RPC Database Server Multiple Vulnerabilities" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "RPC" );
	script_dependencies( "secpod_rpc_portmap_udp.sc", "secpod_rpc_portmap_tcp.sc" );
	script_mandatory_keys( "rpc/portmap" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/975403" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/299816" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/AAMN-5B239R" );
	script_xref( name: "URL", value: "http://www.cert.org/advisories/CA-2002-20.html" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - an error in the handling symbolic link. The server does not check to ensure
  that it is not a symbolic link. If an attacker creates a symbolic link on
  the filesystem with the path/filename of the logfile, transaction data will
  be written to the destination file as root.

  - no available checks to restrict the range of the index value. Consequently,
  malicious file descriptor values supplied by remote clients may cause
  writes to occur far beyond the table in memory. The only value written is
  a NULL word, limiting the consequences." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is running the CDE ToolTalk Database Server and is
  prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to remotely deleting arbitrary
  files and creating arbitrary directory entries. Further, attackers might be
  able to crash the ToolTalk RPC database server, denying service to legitimate users." );
	script_tag( name: "affected", value: "CDE ToolTalk RPC database server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("rpc.inc.sc");
require("byte_func.inc.sc");
RPC_PROG = 100083;
port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_UDP );
if(port){
	security_message( port: port, proto: "udp" );
}
port = rpc_get_port( program: RPC_PROG, protocol: IPPROTO_TCP );
if(port){
	security_message( port: port, proto: "tcp" );
}
exit( 0 );

