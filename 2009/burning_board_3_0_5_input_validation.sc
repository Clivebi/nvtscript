if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100056" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)" );
	script_bugtraq_id( 34057 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Woltlab Burning Board Multiple Input Validation Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Woltlab Burning Board is prone to multiple input-validation vulnerabilities, including:

  - Multiple security that may allow attackers to delete private messages

  - A cross-site scripting vulnerability

  - Multiple URI redirection vulnerabilities

  Attackers can exploit these issues to delete private messages,
  execute arbitrary script code, steal cookie-based authentication
  credentials and redirect users to malicious sites.

 Vulnerable:
  Woltlab Burning Board 3.0.5
  Woltlab Burning Board 3.0.3 PL 1
  Woltlab Burning Board 3.0" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34057" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/forum", "/board", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/wcf/acp/dereferrer.php?url=javascript:alert(document.cookie);" );
	if(http_vuln_check( port: port, url: url, pattern: ".*<a href=.javascript:alert\\(document.cookie\\);.>javascript:alert\\(document.cookie\\);</a>.*", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

