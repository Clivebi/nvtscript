CPE = "cpe:/a:sysaid:sysaid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106006" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2995" );
	script_name( "SysAid < 15.2 Unauthenticated File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sysaid_detect.sc" );
	script_mandatory_keys( "sysaid/detected" );
	script_tag( name: "summary", value: "SysAid Help Desktop Software is prone to a unauthenticated
  file upload vulnerability" );
	script_tag( name: "vuldetect", value: "Determine if the vulnerable service is reachable and then
  check the version." );
	script_tag( name: "insight", value: "The vulnerability exists in the RdsLogsEntry servlet which
  accepts unauthenticated file uploads and handles zip file contents in an insecure way. Note that this
  will only work if the target is running Java 6 or 7 up to 7u25, as Java 7u40 and above introduce a protection
  against null byte injection in file names." );
	script_tag( name: "impact", value: "An unauthenticated attacker can upload arbitrary files which could
  lead to remote code execution." );
	script_tag( name: "affected", value: "SysAid Help Desktop version 15.1.x and before." );
	script_tag( name: "solution", value: "Update to version 15.2 or later." );
	script_xref( name: "URL", value: "https://www.security-database.com/detail.php?alert=CVE-2015-2995" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
dir = infos["location"];
if(!dir){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/rdslogs?rdsName=" + rand_str( length: 4 );
req = NASLString( "POST ", url, " HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n\r\n" );
buf = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( buf, "HTTP/1\\.. 200" ) && version_is_less( version: vers, test_version: "15.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "15.2", install_path: dir );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

