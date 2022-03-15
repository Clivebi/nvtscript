if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111052" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "APC Network Management Card Webinterface Default Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-12 15:00:00 +0100 (Thu, 12 Nov 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote APC Network Management Card Webinterface is
  prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials of apc:apc,
  device:apc or readonly:device." );
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
require("host_details.inc.sc");
port = http_get_port( default: 80 );
useragent = http_get_user_agent();
res = http_get_cache( item: "/logon.htm", port: port );
if(ContainsString( res, "APC Website" ) || ContainsString( res, "http://www.apc.com" ) || ContainsString( res, "<title>APC | Log On</title>" )){
	vuln = FALSE;
	host = http_host_name( port: port );
	report = "It was possible to login using the following credentials:";
	creds = make_array( "apc", "apc", "device", "apc", "readonly", "apc" );
	for cred in keys( creds ) {
		data = NASLString( "login_username=" + cred + "&login_password=" + creds[cred] + "&submit=Log+On" );
		len = strlen( data );
		req = "POST /Forms/login1 HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "Cookie: C0=apc; chkcookie=" + unixtime() + "\r\n" + "\r\n" + data;
		res = http_keepalive_send_recv( port: port, data: req );
		cookie = eregmatch( pattern: "Set-Cookie:APC([0-9a-zA-Z]+)=([0-9a-zA-Z+]+);", string: res );
		if( isnull( cookie[1] ) ){
			cookie = eregmatch( pattern: "Set-Cookie: C0=([0-9a-zA-Z+]+);", string: res );
			if( isnull( cookie[1] ) ){
				cookie = "C0=apc";
			}
			else {
				cookie = "C0=" + cookie[1];
			}
		}
		else {
			cookie = "APC" + cookie[1] + "=" + cookie[2];
		}
		redirect = eregmatch( pattern: "/NMC/([0-9a-zA-Z+]+)/", string: res );
		if( isnull( redirect[1] ) ){
			redirect = "/";
		}
		else {
			redirect = "/NMC/" + redirect[1] + "/";
		}
		req = "GET " + redirect + "home.htm HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: " + cookie + "\r\n" + "\r\n";
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "<a href=\"logout.htm\"" ) && ContainsString( res, "Log Off" )){
			report += "\n\n" + cred + ":" + creds[cred] + "\n";
			vuln = TRUE;
		}
		req = "GET " + redirect + "logout.htm HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: " + cookie + "\r\n" + "\r\n";
		res = http_keepalive_send_recv( port: port, data: req );
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

