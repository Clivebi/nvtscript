if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114049" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:P" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-12-17 19:08:14 +0100 (Mon, 17 Dec 2018)" );
	script_name( "Ubiquiti Networks Unifi Video Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_ubnt_unifi_video_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ubnt/unifi_video/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote installation of Unifi Video is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Unifi Video is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Unifi Video is possible." );
	script_tag( name: "solution", value: "Change the passwords for user and admin access." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/research/blog/default-passwords-for-most-ip-network-camera-brands/" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
CPE = "cpe:/a:ui:unifi_video";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "ubnt", "ubnt", "root", "ubnt", "admin", "admin" );
hostType = get_kb_item( "ubnt/unifi_video/hostType" );
for cred in keys( creds ) {
	if( hostType == "NoSession" ){
		url = "/api/1.1/login";
		data = "{\"username\":\"" + cred + "\",\"password\":\"" + creds[cred] + "\"}";
		req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "DNT", "1", "Content-Type", "application/json", "Accept", "application/json, text/plain, */*" ) );
	}
	else {
		if( hostType == "Session" ){
			url = "/api/2.0/login";
			req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Content-Type", "application/json", "Accept", "application/json, text/javascript, */*; q=0.01", "X-Requested-With", "XMLHttpRequest" ) );
			res = http_send_recv( port: port, data: req );
			sessID = eregmatch( pattern: "Set-Cookie:\\s*JSESSIONID_AV=([0-9a-zA-Z]+);", string: res );
			if(isnull( sessID[1] )){
				continue;
			}
			sessionID = sessID[1];
			data = "{\"username\":\"" + cred + "\",\"password\":\"" + creds[cred] + "\"}";
			req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Content-Type", "application/json", "Accept", "application/json, text/javascript, */*; q=0.01", "X-Requested-With", "XMLHttpRequest", "Cookie", "JSESSIONID_AV=" + sessionID ) );
		}
		else {
			if( hostType == "NoSessionEmail" ){
				url = "/api/2.0/login";
				data = "{\"email\":\"" + cred + "\",\"password\":\"" + creds[cred] + "\"}";
				req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Content-Type", "application/json", "Accept", "application/json, text/javascript, */*; q=0.01", "X-Requested-With", "XMLHttpRequest" ) );
			}
			else {
				exit( 99 );
			}
		}
	}
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "authId=" )){
		VULN = TRUE;
		report += "\nusername: \"" + cred + "\", password: \"" + creds[cred] + "\"";
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

