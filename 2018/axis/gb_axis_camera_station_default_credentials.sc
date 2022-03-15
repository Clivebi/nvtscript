if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114028" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-08-29 12:41:33 +0200 (Wed, 29 Aug 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Axis Camera Station Default Credentials" );
	script_dependencies( "gb_axis_camera_station_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "axis/camerastation/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/blog/tag/default-password-axis/" );
	script_tag( name: "summary", value: "The remote installation of Axis Camera Station is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Axis Camera Station is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Axis Camera Station is possible." );
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
CPE = "cpe:/a:axis:camera_station";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "root", "pass" );
url = "/axis-cgi/param.cgi";
data = "action=listdefinitions&listformat=xmlschema&responseformat=rfc&responsecharset=utf8&group=GuardTour";
for cred in keys( creds ) {
	req1 = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Content-Type", "application/json; charset=utf-8", "Axis-Orig-Sw", "true", "X-Requested-With", "XMLHttpRequest" ) );
	res1 = http_keepalive_send_recv( port: port, data: req1 );
	info = eregmatch( pattern: "Digest realm=\"([^\"]+)\", nonce=\"([^\"]+)\", algorithm=MD5", string: res1 );
	if(isnull( info[1] ) || isnull( info[2] )){
		continue;
	}
	realm = info[1];
	nonce = info[2];
	cnonce = rand_str( charset: "abcdefghijklmnopqrstuvwxyz0123456789", length: 16 );
	qop = "auth";
	nc = "00000001";
	ha1 = hexstr( MD5( NASLString( cred, ":", realm, ":", creds[cred] ) ) );
	ha2 = hexstr( MD5( NASLString( "POST:", url ) ) );
	response = hexstr( MD5( NASLString( ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2 ) ) );
	auth = "Digest username=\"" + cred + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + url + "\", algorithm=MD5, response=\"" + response + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";
	req2 = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Content-Type", "application/json; charset=utf-8", "Axis-Orig-Sw", "true", "X-Requested-With", "XMLHttpRequest", "Authorization", auth ) );
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(ContainsString( res2, "axis" ) && ContainsString( res2, "<firmwareVersion>" )){
		VULN = TRUE;
		report += "\nusername: \"" + cred + "\", password: \"" + creds[cred] + "\"";
		firmVer = eregmatch( pattern: "<firmwareVersion>([0-9.]+)</firmwareVersion>", string: res2 );
		if(firmVer[1]){
			set_kb_item( name: "axis/camerastation/firmware/version", value: firmVer[1] );
		}
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

