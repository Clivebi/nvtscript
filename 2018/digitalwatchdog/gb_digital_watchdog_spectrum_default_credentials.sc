if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114035" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-09-18 13:56:20 +0200 (Tue, 18 Sep 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Digital Watchdog Spectrum Default Credentials" );
	script_dependencies( "gb_digital_watchdog_spectrum_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 7001 );
	script_mandatory_keys( "digital_watchdog/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/blog/tag/default-password-axis/" );
	script_tag( name: "summary", value: "The remote installation of Digital Watchdog Spectrum is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Digital Watchdog Spectrum is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Digital Watchdog Spectrum is possible." );
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
CPE = "cpe:/h:digital_watchdog:spectrum";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url = "/api/getCurrentUser";
for cred in keys( creds ) {
	req1 = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Accept", "application/json, text/plain, */*" ) );
	res1 = http_keepalive_send_recv( port: port, data: req1 );
	info = eregmatch( pattern: "X-server-guid: (\\{[^\"]+\\}).*WWW-Authenticate: Digest realm=\"([^\"]+)\", nonce=\"([^\"]+)\", algorithm=MD5", string: res1 );
	if(isnull( info[1] ) || isnull( info[2] ) || isnull( info[3] )){
		continue;
	}
	xguid = info[1];
	realm = info[2];
	nonce = info[3];
	ha1 = hexstr( MD5( NASLString( tolower( cred ), ":", realm, ":", creds[cred] ) ) );
	ha2 = hexstr( MD5( NASLString( ha1, ":", nonce, ":", hexstr( MD5( NASLString( "GET", ":" ) ) ) ) ) );
	auth = base64( str: NASLString( tolower( cred ), ":", nonce, ":", ha2 ) );
	ha2_rtsp = hexstr( MD5( NASLString( ha1, ":", nonce, ":", hexstr( MD5( NASLString( "PLAY", ":" ) ) ) ) ) );
	auth_rtsp = base64( str: NASLString( tolower( cred ), ":", nonce, ":", ha2_rtsp ) );
	auth_header = "X-runtime-guid=" + xguid + "; Authorization=Digest; nonce=" + nonce + "; realm=" + realm + "; auth=" + auth + "; auth_rtsp=" + auth_rtsp;
	req2 = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Accept", "application/json, text/plain, */*", "Cookie", auth_header ) );
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(ContainsString( res2, "{\"error\": \"0\"" ) && ContainsString( res2, "\"reply\": {\"cryptSha512Hash\":" )){
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

