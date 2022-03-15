if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803437" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 58441 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-14 13:10:16 +0530 (Thu, 14 Mar 2013)" );
	script_name( "Web Cookbook Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24742" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120760/" );
	script_xref( name: "URL", value: "http://security-geeks.blogspot.in/2013/03/web-cookbook-sql-injection-xss.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML or web script in a user's browser session in context of an affected site,
  compromise the application and inject or manipulate SQL queries in the
  back-end database." );
	script_tag( name: "affected", value: "Web Cookbook versions 0.9.9 and prior" );
	script_tag( name: "insight", value: "Input passed via 'sstring', 'mode', 'title', 'prefix', 'postfix',
  'preparation', 'tipp', 'ingredient' parameters to searchrecipe.php,
  showtext.php, searchrecipe.php scripts is not properly sanitised before
  being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Web Cookbook and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/", "/cookbook", "/webcookbook", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(rcvRes && ContainsString( rcvRes, "/projects/webcookbook/" )){
		url = dir + "/searchrecipe.php?mode=1&title=<script>alert('XSS-Test')</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\('XSS-Test'\\)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

