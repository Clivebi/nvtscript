if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100766" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-31 14:30:50 +0200 (Tue, 31 Aug 2010)" );
	script_bugtraq_id( 42478 );
	script_name( "123 Flash Chat Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42478" );
	script_xref( name: "URL", value: "http://123flashchat.com/" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 35555 );
	script_mandatory_keys( "TopCMM/banner" );
	script_tag( name: "summary", value: "123 Flash Chat is prone to multiple security vulnerabilities. These
  vulnerabilities include a cross-site scripting vulnerability, multiple
  information-disclosure vulnerabilities, and a directory-traversal vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit these vulnerabilities to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site, steal cookie-based authentication credentials,
  obtain sensitive information, or perform unauthorized actions. Other
  attacks are also possible." );
	script_tag( name: "affected", value: "123 Flash Chat 7.8 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 35555 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: TopCMM Server" )){
	exit( 0 );
}
url = NASLString( "/index.html%27%22--%3E%3Cscript%3Ealert%28%27vt-xss-test%27%29%3C/script%3E" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\)</script>", extra_check: "Error Information", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

