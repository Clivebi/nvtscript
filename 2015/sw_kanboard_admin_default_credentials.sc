CPE = "cpe:/a:kanboard:kanboard";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111064" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Kanboard admin default credentials" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2015-12-04 13:00:00 +0100 (Fri, 04 Dec 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "sw_kanboard_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "kanboard/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Kanboard web interface is prone to a default account
  authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials: admin/admin" );
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
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
controllers = make_list( dir + "/?controller=auth",
	 dir + "/?controller=user" );
for controller in controllers {
	req = http_get( item: controller + "&action=login", port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	cookie = eregmatch( pattern: "KB_SID=([0-9a-zA-Z%-]+);", string: res );
	if(isnull( cookie[1] )){
		cookie = eregmatch( pattern: "__S=([0-9a-zA-Z%-]+);.*__S=([0-9a-zA-Z%-]+);", string: res );
		if( !isnull( cookie[2] ) ){
			cookie[0] = "__S=" + cookie[2];
		}
		else {
			cookie = eregmatch( pattern: "__S=([0-9a-zA-Z%-]+);", string: res );
		}
	}
	csrftoken = eregmatch( pattern: "name=\"csrf_token\" value=\"([0-9a-z]+)\"", string: res );
	host = http_host_name( port: port );
	useragent = http_get_user_agent();
	if( isnull( csrftoken[1] ) ){
		data = NASLString( "username=admin&password=admin&remember_me=0" );
	}
	else {
		data = NASLString( "csrf_token=" + csrftoken[1] + "&username=admin&password=admin&remember_me=0" );
	}
	len = strlen( data );
	req = "POST " + controller + "&action=check HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: " + cookie[0] + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: port, data: req );
	req = "GET " + dir + "/?controller=config&action=index HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: " + cookie[0] + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "\r\n";
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<title>Settings" ) || ContainsString( res, "Logout</a>" )){
		report = "It was possible to login at \"" + dir + "\" using the following credentials:\n\nadmin:admin\n";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

