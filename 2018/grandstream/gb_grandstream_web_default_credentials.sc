if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114019" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-08-08 13:17:57 +0200 (Wed, 08 Aug 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Grandstream Web UI Default Credentials" );
	script_dependencies( "gb_grandstream_web_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "grandstream/webui/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://cirt.net/passwords" );
	script_tag( name: "summary", value: "The remote Grandstream Web UI is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Grandstream Web UI is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Grandstream Web UI is possible." );
	script_tag( name: "solution", value: "Change the passwords for user and admin access." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
CPE = "cpe:/a:grandstream:web_ui";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url1 = "/cgi-bin/login";
url2 = "/cgi-bin/dologin";
res1 = http_get_cache( port: port, item: url1 );
sessionToken = eregmatch( pattern: "<input name=\"session_token\" type=hidden value=\"([0-9a-zA-Z]+)\">", string: res1 );
if(sessionToken[1]){
	sessionID = sessionToken[1];
}
loginTypes = make_list( 0,
	 1 );
for loginType in loginTypes {
	if( !loginType ){
		data = "session_token=" + sessionID + "&username=admin&P2=admin&Login=Login&gnkey=0b82";
	}
	else {
		data = "P2=123&Login=Login&gnkey=0b82";
	}
	req = http_post_put_req( port: port, url: url2, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<b>Software Version: </b>" ) || ContainsString( res, "<b>BASIC SETTINGS</b>" ) || ContainsString( res, "<b>ADVANCED SETTINGS</b>" )){
		vers = eregmatch( pattern: "Program\\s*--\\s*([0-9.]+)", string: res );
		if(vers[1]){
			version = vers[1];
			set_kb_item( name: "grandstream/webui/version", value: version );
		}
		if( !loginType ){
			report = "It was possible to login via the default admin password \"admin\".";
		}
		else {
			report = "It was possible to login via the default user password \"123\".";
			url3 = "/cgi-bin/doadminlogin";
			data = "P2=admin&Login=Login&gnkey=0b82";
			req = http_post_put_req( port: port, url: url3, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", "session_id=" + sessionID ) );
			res = http_keepalive_send_recv( port: port, data: req );
			if(ContainsString( res, "<b>Admin Password: </b>" ) || ContainsString( res, "<i>Keep-alive Interval: </i>" ) || ContainsString( res, "<i>ACS Username: </i>" ) || ContainsString( res, "<input type=\"submit\" name=\"update\"" ) || ContainsString( res, "<input type=\"submit\" name=\"apply\"" )){
				report += "\r\nIt was also possible to login via the default admin password \"admin\".";
			}
		}
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

