if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103703" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "ARRIS 2307 Unprotected Web Console" );
	script_xref( name: "URL", value: "http://www.arrisi.com/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-23 12:01:48 +0100 (Tue, 23 Apr 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "The remote ARRIS 2307 Web Console is not protected by a password." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/login.html";
res = http_get_cache( item: url, port: port );
if(ContainsString( res, "content=\"ARRIS 2307\"" )){
	useragent = http_get_user_agent();
	host = http_host_name( port: port );
	login = "page=&logout=&action=submit&pws=";
	len = strlen( login );
	req = NASLString( "POST /login.cgi HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\\r\\n", "Accept-Encoding: identity\\r\\n", "DNT: 1\\r\\n", "Connection: keep-alive\\r\\n", "Referer: http://", host, "/login.html\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", login );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( result, "lan_ipaddr" ) && ContainsString( result, "http_passwd" ) && ContainsString( result, "userNewPswd" )){
		security_message( port: port );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

