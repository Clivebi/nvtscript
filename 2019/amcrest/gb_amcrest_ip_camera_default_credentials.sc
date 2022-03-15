if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114085" );
	script_version( "2020-04-12T06:48:30+0000" );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-12 06:48:30 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2019-03-15 15:02:42 +0100 (Fri, 15 Mar 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Amcrest Technologies IP Camera Default Credentials" );
	script_dependencies( "gb_amcrest_ip_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "amcrest/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://support.amcrest.com/hc/en-us/articles/360002043651-How-To-Access-Your-Web-UI" );
	script_tag( name: "summary", value: "The remote installation of Amcrest's IP camera software is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Amcrest's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Amcrest's IP camera software is possible." );
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
CPE = "cpe:/a:amcrest:ip_camera";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin", "anonymity", "anonymity" );
url = "/RPC2_Login";
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	id = 1;
	data = "{\"method\":\"global.login\",\"params\":{\"userName\":\"" + username + "\",\"password\":\"\",\"clientType\":\"Web3.0\",\"loginType\":\"Direct\"},\"id\":" + id + "}";
	req = http_post_put_req( port: port, url: url, data: data );
	res = http_keepalive_send_recv( port: port, data: req );
	info = eregmatch( pattern: "\"encryption\"\\s*:\\s*\"([^\"]+)\"(,\"mac\":\"[^\"]*\")?,\\s*\"random\"\\s*:\\s*\"([^\"]+)\",\\s*\"realm\"\\s*:\\s*\"([^\"]+)\"\\s*},\\s*\"result\"\\s*:\\s*[^,]*,\\s*\"session\"\\s*:\\s*([^}]+)\\s*}", string: res, icase: TRUE );
	if(isnull( info[1] ) || isnull( info[3] ) || isnull( info[4] ) || isnull( info[5] )){
		continue;
	}
	encryption = info[1];
	random = info[3];
	realm = info[4];
	sessionID = int( info[5] );
	if( encryption == "Basic" ){
		pass = base64( str: username + ":" + password );
	}
	else {
		if( encryption == "Default" ){
			ha1 = toupper( hexstr( MD5( NASLString( username, ":", realm, ":", password ) ) ) );
			pass = toupper( hexstr( MD5( NASLString( username, ":", random, ":", ha1 ) ) ) );
		}
		else {
			pass = password;
		}
	}
	data = "{\"method\":\"global.login\",\"params\":{\"userName\":\"" + username + "\",\"password\":\"" + pass + "\",\"clientType\":\"Web3.0\",\"loginType\":\"Direct\",\"authorityType\":\"" + encryption + "\"},\"id\":" + ++id + ",\"session\":" + sessionID + "}";
	req = http_post_put_req( port: port, url: url, data: data );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "\"result\"\\s*:\\s*true" )){
		VULN = TRUE;
		if(!password){
			password = "<no/empty password>";
		}
		report += "\n" + username + ":" + password;
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials (username:password):\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

