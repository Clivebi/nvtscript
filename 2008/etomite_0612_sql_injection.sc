if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80057" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-6048" );
	script_bugtraq_id( 21135 );
	script_xref( name: "OSVDB", value: "30442" );
	script_name( "Etomite CMS id Parameter SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "summary", value: "The remote web server contains a PHP script that is affected by a SQL
  injection vulnerability.

  Description:

  The remote web server is running Etomite CMS, a PHP-based content
  management system.

  The version of Etomite CMS installed on the remote host fails to
  sanitize input to the 'id' parameter before using it in the
  'index.php' script in a database query." );
	script_tag( name: "impact", value: "Provided PHP's 'magic_quotes_gpc' setting is disabled, an unauthenticated
  attacker can exploit this issue to manipulate SQL queries, possibly leading to disclosure of sensitive data,
  attacks against the underlying database, and the like." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/451838/30/0/threaded" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
injectstring = rand_str( charset: "abcdefghijklmnopqrstuvwxyz0123456789_", length: 10 );
for dir in nasl_make_list_unique( "/etomite", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?id=", injectstring, "'" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!res){
		continue;
	}
	sqlstring = "";
	if(ContainsString( res, NASLString( "etomite_site_content.id = '", injectstring ) )){
		sqlstring = res;
		if(ContainsString( sqlstring, "<span id='sqlHolder'>" )){
			sqlstring = strstr( sqlstring, "SELECT" );
		}
		if(ContainsString( sqlstring, "</span></b>" )){
			sqlstring = sqlstring - strstr( sqlstring, "</span></b>" );
		}
		info = NASLString( "The version of Etomite CMS installed in directory '", dir, "'\\n", "is vulnerable to this issue. Here is the resulting SQL string\\n", "from the remote host when using a test string of '", injectstring, "'  :\\n\\n", sqlstring );
		security_message( data: info, port: port );
		exit( 0 );
	}
}
exit( 99 );

