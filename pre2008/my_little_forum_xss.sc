if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11960" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 9286 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "My Little Forum XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/10489/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/14066" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1008545" );
	script_xref( name: "URL", value: "http://www.os2world.com/content/view/12704/79/" );
	script_tag( name: "summary", value: "The remote host is running 'My Little Forum', a free CGI suite to manage
  discussion forums.

  This PHP/MySQL based forum suffers from a Cross Site Scripting vulnerability. This can be exploited by
  including arbitrary HTML or even JavaScript code in the parameters (forum_contact, category and page),
  which will be executed in user's browser session when viewed." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod", value: "50" );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
quote = raw_string( 0x22 );
for dir in nasl_make_list_unique( "/", "/forum", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/email.php?forum_contact=" + quote + "><script>foo</script>";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>foo</script>" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

