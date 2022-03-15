if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16279" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Uebimiau Session Directory Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Uebimiau in default installation create one temporary folder
  to store 'sessions' and other files. This folder is defined  in 'inc/config.php' as './database/'." );
	script_tag( name: "impact", value: "If the web administrator don't change this folder, an attacker
  can exploit this using the follow request:

  http://example.com/database/_sessions/" );
	script_tag( name: "solution", value: "1) Insert index.php in each directory of the Uebimiau

  2) Set variable $temporary_directory to a directory not public and with restricted access,
  set permission as read only to 'web server user' for each files in $temporary_directory.

  3) Set open_basedir in httpd.conf to yours clients follow the model below:

  <Directory /server-target/public_html>

    php_admin_value open_basedir

    /server-target/public_html

  </Directory>" );
	script_tag( name: "affected", value: "Uebimiau <= 2.7.2 are known to be vulnerable. Other versions might
  be affected as well." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/mailpop", "/webmail", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/database/_sessions/";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!res){
		continue;
	}
	if(( ContainsString( res, "Parent Directory" ) ) && ( ContainsString( res, "/database/_sessions" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

