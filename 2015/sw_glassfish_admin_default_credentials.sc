CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111073" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-12-17 15:00:00 +0100 (Thu, 17 Dec 2015)" );
	script_name( "Oracle GlassFish Admin Default Credentials" );
	script_tag( name: "summary", value: "The remote Oracle GlassFish is prone to a default
  account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials 'admin:admin'
  or 'admin:'" );
	script_tag( name: "solution", value: "Change the password." );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "GlassFish_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 4848 );
	script_mandatory_keys( "GlassFish/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
if(!get_kb_item( "www/" + port + "/GlassFishAdminConsole" )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
cookie = eregmatch( pattern: "JSESSIONID=([0-9a-zA-Z]+);", string: res );
if(isnull( cookie[1] )){
	exit( 0 );
}
credentials = make_list( "admin:admin",
	 "admin:none" );
host = http_host_name( port: port );
useragent = http_get_user_agent();
for credential in credentials {
	user_pass = split( buffer: credential, sep: ":", keep: FALSE );
	user = chomp( user_pass[0] );
	pass = chomp( user_pass[1] );
	if(tolower( pass ) == "none"){
		pass = "";
	}
	data = NASLString( "j_username=" + user + "&j_password=" + pass + "&loginButton=Login&loginButton.DisabledHiddenField=true" );
	len = strlen( data );
	req = "POST /j_security_check HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Referer: http://" + host + "/\r\n" + "Cookie: JSESSIONID=" + cookie[1] + "\r\n" + "Connection: keep-alive\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: port, data: req );
	if(( IsMatchRegexp( res, "HTTP/1.. 302 Moved Temporarily" ) || IsMatchRegexp( res, "HTTP/1.. 302 Found" ) ) && ContainsString( res, "/\">here" )){
		cookie = eregmatch( pattern: "JSESSIONID=([0-9a-zA-Z]+);", string: res );
		if(isnull( cookie[1] )){
			exit( 0 );
		}
		req = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Referer: http://" + host + "/\r\n" + "Cookie: JSESSIONID=" + cookie[1] + "\r\n" + "Connection: keep-alive\r\n" + "\r\n";
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		req = "GET /common/index.jsf HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Referer: http://" + host + "/\r\n" + "Cookie: JSESSIONID=" + cookie[1] + "\r\n" + "Connection: keep-alive\r\n" + "\r\n";
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( res, "<title>Common Tasks</title>" ) || ContainsString( res, "Log Out of GlassFish Administration Console" ) || ContainsString( res, "<title>GlassFish Console - Common Tasks</title>" )){
			report = http_report_vuln_url( port: port, url: "/common/index.jsf" );
			report = report + "\n\nIt was possible to login using the following credentials:\n\n" + user + ":" + pass + "\n";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

