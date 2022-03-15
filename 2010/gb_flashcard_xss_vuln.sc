if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801211" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_cve_id( "CVE-2010-1872" );
	script_bugtraq_id( 39648 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "FlashCard 'cPlayer.php' Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39484" );
	script_xref( name: "URL", value: "http://www.xenuser.org/documents/security/flashcard_xss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code in the context of an affected site." );
	script_tag( name: "affected", value: "FlashCard Version 2.6.5 and 3.0.1" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'id' parameter in 'cPlayer.php' that allows the attackers to execute
  arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running FlashCard and is prone to cross-site
  scripting vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/", "/flashcard", "/FlashCard", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, "<TITLE>FlashCard " )){
		req = http_get( item: NASLString( dir, "/cPlayer.php?id=%22%3E%3Ciframe%20src=", "http://", get_host_ip(), dir, "/register.php%3E" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(eregmatch( pattern: "\"><iframe src=http://.*register.php>", string: res )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

