if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114041" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 15:43:28 +0200 (Fri, 26 Oct 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Hikvision IP Camera Default Credentials" );
	script_dependencies( "gb_hikvision_ip_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8081 );
	script_mandatory_keys( "hikvision/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/blog/tag/default-password-axis/" );
	script_tag( name: "summary", value: "The remote installation of Hikvision IP camera is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Hikvision IP camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Hikvision IP camera is possible." );
	script_tag( name: "solution", value: "Change the passwords for user and admin access." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
CPE = "cpe:/a:hikvision:ip_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "12345" );
url2 = "/ISAPI/Security/userCheck?timeStamp=" + unixtime();
for cred in keys( creds ) {
	url1 = "/ISAPI/Security/sessionLogin/capabilities?username=" + cred;
	req1 = http_get_req( port: port, url: url1 );
	res1 = http_keepalive_send_recv( port: port, data: req1 );
	if( ContainsString( res1, "<challenge>" ) && ContainsString( res1, "<iterations>" ) ){
		info = eregmatch( pattern: "<sessionID>([0-9a-zA-Z]+)</sessionID>\\s*\\n?\\s*<challenge>([0-9a-zA-Z]+)</challenge>\\s*\\n?\\s*<iterations>([0-9]+)</iterations>", string: res1 );
		infoSalt = eregmatch( pattern: "<isIrreversible>([a-zA-Z]+)</isIrreversible>\\s*\\n?\\s*<salt>([0-9a-zA-Z]+)</salt>", string: res1 );
		if(isnull( info[1] ) || isnull( info[2] ) || isnull( info[3] )){
			continue;
		}
		sessionID = info[1];
		challenge = info[2];
		iterations = int( info[3] );
		if( !isnull( infoSalt[1] ) && !isnull( infoSalt[2] ) ){
			if( IsMatchRegexp( infoSalt[1], "(t|T)rue" ) ) {
				isIrreversible = 1;
			}
			else {
				isIrreversible = 0;
			}
			salt = infoSalt[2];
			if( isIrreversible ){
				pass = hexstr( SHA256( cred + salt + creds[cred] ) );
				pass = hexstr( SHA256( pass + challenge ) );
				for(a = 2;iterations > a;a++){
					pass = hexstr( SHA256( pass ) );
				}
			}
			else {
				pass = hexstr( SHA256( creds[cred] ) ) + challenge;
				for(a = 1;iterations > a;a++){
					pass = hexstr( SHA256( pass ) );
				}
			}
		}
		else {
			pass = hexstr( SHA256( creds[cred] ) ) + challenge;
			for(m = 1;iterations > m;m++){
				pass = hexstr( SHA256( pass ) );
			}
		}
		data = "<SessionLogin><userName>" + cred + "</userName><password>" + pass + "</password><sessionID>" + sessionID + "</sessionID></SessionLogin>";
		url3 = "/ISAPI/Security/sessionLogin?timeStamp=" + unixtime();
		req2 = http_post_put_req( port: port, url: url3, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "If-Modified-Since", "0", "X-Requested-With", "XMLHttpRequest", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ) );
	}
	else {
		if( ( ContainsString( res1, "Digest qop=" ) && ContainsString( res1, "nonce=" ) ) || ( ContainsString( res1, "Digest realm=" ) && ContainsString( res1, "nonce=" ) ) ){
			info = eregmatch( pattern: "WWW-Authenticate:\\s*Digest realm=\"([^\"]+)\",\\s*domain=\"[^\"]+\",\\s*qop=\"([^\"]+)\",\\s*nonce=\"([^\"]+)\",\\s*opaque=\"\",\\s*algorithm=\"MD5\"", string: res1 );
			if( !isnull( info[1] ) && !isnull( info[2] ) && !isnull( info[3] ) ){
				realm = info[1];
				qop = info[2];
				nonce = info[3];
			}
			else {
				info = eregmatch( pattern: "WWW-Authenticate:\\s*Digest qop=\"([^\"]+)\",\\s*realm=\"([^\"]+)\",\\s*nonce=\"([^\"]+)\",", string: res1 );
				if(isnull( info[1] ) || isnull( info[2] ) || isnull( info[3] )){
					continue;
				}
				qop = info[1];
				realm = info[2];
				nonce = info[3];
			}
			cnonce = rand_str( charset: "abcdefghijklmnopqrstuvwxyz0123456789", length: 16 );
			nc = "00000001";
			ha1 = hexstr( MD5( NASLString( cred, ":", realm, ":", creds[cred] ) ) );
			ha2 = hexstr( MD5( NASLString( "GET:", url2 ) ) );
			response = hexstr( MD5( NASLString( ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2 ) ) );
			auth = "Digest username=\"" + cred + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + url2 + "\", algorithm=MD5, response=\"" + response + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";
			req2 = http_get_req( port: port, url: url2, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "If-Modified-Since", "0", "X-Requested-With", "XMLHttpRequest", "Authorization", auth ) );
		}
		else {
			exit( 99 );
		}
	}
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(ContainsString( res2, "<statusValue>200</statusValue>" ) && ContainsString( res2, "<statusString>OK</statusString>" )){
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

