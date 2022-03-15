if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114040" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-10-15 21:06:41 +0200 (Mon, 15 Oct 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Dahua Devices Default Credentials" );
	script_dependencies( "gb_dahua_devices_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dahua/device/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/blog/tag/default-password-axis/" );
	script_tag( name: "summary", value: "The remote installation of Dahua's ip camera software (or a derivative of such)
  is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Dahua's ip camera software (or a derivative of such)  is
  lacking a proper password configuration, which makes critical information and actions accessible for people with
  knowledge of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Dahua's ip camera software is possible." );
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
CPE = "cpe:/a:dahua:nvr";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin", "000000", "admin" );
url = "/RPC2_Login";
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	id = "1" + rand_str( length: 4, charset: "1234567890" );
	data = "{\"method\":\"global.login\",\"params\":{\"userName\":\"" + username + "\",\"password\":\"\",\"clientType\":\"Dahua3.0-Web3.0\"},\"id\":" + id + "}";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "X-Request", "JSON", "Accept", "text/javascript, text/html, application/xml, text/xml, */*" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	sess = eregmatch( pattern: "\"session\"\\s*:\\s*([0-9]+)\\s*\\}", string: res );
	if( !isnull( sess[1] ) ) {
		sessionID = sess[1];
	}
	else {
		continue;
	}
	encryp = eregmatch( pattern: "\"encryption\"\\s*:\\s*\"([a-zA-Z]+)\"", string: res );
	if( !isnull( encryp[1] ) ) {
		encryptionType = encryp[1];
	}
	else {
		encryptionType = "";
	}
	random = eregmatch( pattern: "\"random\"\\s*:\\s*\"([^\"]+)\"", string: res );
	if( !isnull( random[1] ) ) {
		random_string = random[1];
	}
	else {
		if(encryptionType == "Default"){
			break;
		}
	}
	rea = eregmatch( pattern: "\"realm\"\\s*:\\s*\"([^\"]+)\"", string: res );
	if( !isnull( rea[1] ) ) {
		realm = rea[1];
	}
	else {
		realm = "";
	}
	if( encryptionType == "Basic" ){
		pass = base64( str: username + ":" + password );
	}
	else {
		if( encryptionType == "Default" ){
			HA1 = hexstr( MD5( NASLString( username, ":", realm, ":", password ) ) );
			pass = hexstr( MD5( NASLString( username, ":", random_string, ":", HA1 ) ) );
		}
		else {
			if( encryptionType == "OldDigest" ){
				if( password == "admin" ) {
					pass = "6QNMIQGe";
				}
				else {
					break;
				}
			}
			else {
				pass = password;
			}
		}
	}
	data = "{\"method\":\"global.login\",\"session\":" + sessionID + ",\"params\":{\"userName\":\"" + username + "\",\"password\":\"" + pass + "\",\"clientType\":\"Dahua3.0-Web3.0\", \"authorityType\":\"" + encryptionType + "\"},\"id\":" + id + "}";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "X-Request", "JSON", "X-Requested-With", "XMLHttpRequest", "Dhwebclientsessionid", sessionID, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", "Accept", "text/javascript, text/html, application/xml, text/xml, */*" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "\"result\"\\s*:\\s*true" ) && IsMatchRegexp( res, "\"params\"\\s*:\\s*null" )){
		VULN = TRUE;
		report += "\nusername: \"" + username + "\", password: \"" + password + "\"";
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

