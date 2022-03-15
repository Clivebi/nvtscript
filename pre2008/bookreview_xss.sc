if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18375" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2005-1782" );
	script_bugtraq_id( 13783 );
	script_xref( name: "OSVDB", value: "16871" );
	script_xref( name: "OSVDB", value: "16872" );
	script_xref( name: "OSVDB", value: "16873" );
	script_xref( name: "OSVDB", value: "16874" );
	script_xref( name: "OSVDB", value: "16875" );
	script_xref( name: "OSVDB", value: "16876" );
	script_xref( name: "OSVDB", value: "16877" );
	script_xref( name: "OSVDB", value: "16878" );
	script_xref( name: "OSVDB", value: "16879" );
	script_xref( name: "OSVDB", value: "16880" );
	script_xref( name: "OSVDB", value: "16881" );
	script_name( "BookReview Multiple Cross-Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote web server contains a CGI which is vulnerable to multiple cross site
  scripting vulnerabilities.

  Description :

  The remote host is running the BookReview software.

  The remote version of this software is vulnerable to multiple cross-site
  scripting vulnerabilities due to a lack of sanitization of user-supplied data.

  Successful exploitation of this issue may allow an attacker to use the
  remote server to perform an attack against a third-party user." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('XSS'\\)</script>", extra_check: "Powered by BookReview", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

