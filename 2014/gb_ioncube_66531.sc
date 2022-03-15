if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103932" );
	script_bugtraq_id( 66531 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_name( "ionCube Loader Wizard 'loader-wizard.php' Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/66531" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-04-01 13:11:55 +0200 (Tue, 01 Apr 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "ionCube Loader is prone to the following security vulnerabilities:

  1. A cross-site scripting vulnerability

  2. An information-disclosure vulnerabilities

  3. An Arbitrary File Disclosure Vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "An attacker can exploit these issues to obtain potentially sensitive
  information, to view arbitrary files from the local filesystem and to execute arbitrary script code in
  the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials to launch other attacks." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "ionCube Loader is prone to multiple security vulnerabilities." );
	script_tag( name: "affected", value: "Versions prior to ionCube Loader 2.46 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/ioncube", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/loader-wizard.php?page=phpinfo";
	if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo()" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

