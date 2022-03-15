if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19947" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-3063" );
	script_bugtraq_id( 14933 );
	script_name( "MailGust SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Ferdy Riphagen" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "A vulnerability was identified in MailGust, which may be
  exploited by remote attackers to execute arbitrary SQL commands." );
	script_xref( name: "URL", value: "http://retrogod.altervista.org/maildisgust.html" );
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
for dir in nasl_make_list_unique( "/mailgust", "/forum", "/maillist", "/gust", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(!res){
		continue;
	}
	if(egrep( pattern: ">Powered by <a href=[^>]+>Mailgust", string: res )){
		host = http_host_name( port: port );
		req = NASLString( "POST ", url, " HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: 64\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n\\r\\n", "method=remind_password&list=maillistuser&email='&showAvatar=\\r\\n\\r\\n" );
		recv = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!recv){
			continue;
		}
		if(egrep( pattern: "SELECT.*FROM.*WHERE", string: recv )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

