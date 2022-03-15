if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111053" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Silex USB-device Webinterface Default Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-13 15:00:00 +0100 (Fri, 13 Nov 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Silex USB-device Webinterface is prone to a
  default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials 'root'
  and an empty password." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
req = http_get( item: "/en/status/devstat.htm", port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
useragent = http_get_user_agent();
if(ContainsString( res, "<title>Device Status" )){
	req = http_get( item: "/en/setup", port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	auth = base64( str: "root:" );
	host = http_host_name( port: port );
	req = "GET /en/setup/ HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Authorization: Basic " + auth + "\r\n" + "\r\n";
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "dserv_h.htm" ) && ContainsString( res, "network.htm" )){
		report = "It was possible to login using the following credentials:\n\nroot:\n";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

