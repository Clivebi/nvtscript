if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802260" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)" );
	script_cve_id( "CVE-2011-1248" );
	script_bugtraq_id( 47730 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows WINS Remote Code Execution Vulnerability (2524426)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "find_service.sc", "os_detection.sc" );
	script_require_ports( 42 );
	script_mandatory_keys( "Host/runs_windows" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/67100" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17830/" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-11-167/" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-035" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code with elevated privileges or cause a denial-of-service condition." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by a logic error in the Windows Internet Name Service
  (WINS) when handling a socket send exception, which could cause certain user
  supplied values to remain within a stack frame and to be reused in another
  context, leading to arbitrary code execution with elevated privileges." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-035." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("byte_func.inc.sc");
port = 42;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
start_assoc = mkdword( 0x00007800 ) + mkdword( 0x00000000 ) + mkdword( 0x00000000 ) + mkdword( 0x00000042 ) + mkword( 0x0002 ) + mkword( 0x0005 );
req = start_assoc + crap( length: 0x15 );
req = mkdword( strlen( req ) ) + req;
send( socket: soc, data: req );
res = recv( socket: soc, length: 1024 );
if(!res){
	exit( 0 );
}
assoc_ctx = getdword( blob: res, pos: 8 );
if(assoc_ctx != 0x00000042){
	exit( 0 );
}
stop_assoc = mkdword( 0x00007800 ) + mkdword( 0x00000040 ) + mkdword( 0x00000002 ) + mkdword( 0x00000000 ) + crap( length: 0x18 );
stop_assoc = mkdword( strlen( stop_assoc ) ) + stop_assoc;
send( socket: soc, data: stop_assoc );
close( soc );
soc1 = open_sock_tcp( port );
if(!soc1){
	exit( 0 );
}
req1 = mkdword( strlen( start_assoc ) ) + start_assoc;
send( socket: soc1, data: req1 );
res = recv( socket: soc1, length: 1024 );
if(res){
	security_message( port );
	send( socket: soc1, data: stop_assoc );
}
close( soc1 );

