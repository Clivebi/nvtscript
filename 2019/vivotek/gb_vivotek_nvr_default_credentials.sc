if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114061" );
	script_version( "2020-11-11T14:11:33+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-11-11 14:11:33 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-05-03 13:36:20 +0200 (Fri, 03 May 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Vivotek NVR Default Credentials" );
	script_dependencies( "gb_vivotek_nvr_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vivotek/nvr/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/research/blog/default-passwords-for-most-ip-network-camera-brands/" );
	script_xref( name: "URL", value: "https://www.use-ip.co.uk/forum/threads/vivotek-default-login-username-and-password.384/" );
	script_tag( name: "summary", value: "The remote installation of Vivotek NVR is using known
  and deffault credentials for its web interface." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Vivotek NVR is lacking a proper
  password configuration, which makes critical information and actions accessible to anyone." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to the IP camera management software is possible." );
	script_tag( name: "solution", value: "Change the default credentials." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("string_hex_func.inc.sc");
require("http_func.inc.sc");
require("dump.inc.sc");
CPE = "cpe:/a:vivotek:nvr";
if(!defined_func( "rsa_public_encrypt" )){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url1 = "/fcgi-bin/system.key";
url2 = "/fcgi-bin/system.login";
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	cookie = "_SID_=; username=" + username + "; nvr_user=; mode=liveview";
	req = http_get_req( port: port, url: url1, add_headers: make_array( "Cookie", cookie ) );
	res = http_send_recv( port: port, data: req );
	expMod = eregmatch( pattern: "\\{\"e\":\\s*\"([01]+)\",\\s*\"n\":\\s*\"([0-9a-fA-F]+)\"\\}", string: res );
	if( !isnull( expMod[1] ) && !isnull( expMod[2] ) ){
		modLength = strlen( expMod[2] );
		if(strlen( expMod[1] ) % 2){
			expMod[1] = "0" + expMod[1];
		}
		if(strlen( expMod[2] ) % 2){
			expMod[2] = "0" + expMod[2];
		}
		rsa_exponent = hex2raw( s: expMod[1] );
		rsa_modulus = hex2raw( s: expMod[2] );
	}
	else {
		exit( 99 );
	}
	pad = rand_str( charset: "abcdef0123456789", length: 8 );
	text = ":" + username + ":" + password;
	if( modLength == 256 ){
		seg_l = 117;
		encode_l = 234;
	}
	else {
		seg_l = 53;
		encode_l = 159;
	}
	pad_l = encode_l - strlen( text );
	for(i = strlen( pad );i < pad_l;i += i){
		pad += pad;
	}
	text = substr( pad, 0, pad_l - 1 ) + text;
	for(l = 0;l < encode_l;l += seg_l){
		resultHash += hexstr( rsa_public_encrypt( data: substr( text, l, l + seg_l ), e: rsa_exponent, n: rsa_modulus, pad: "TRUE" ) );
	}
	auth = "Basic " + resultHash;
	data = "encode=" + resultHash + "&mode=liveview";
	req = http_post_put_req( port: port, url: url2, data: data, add_headers: make_array( "Authorization", auth ) );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "{\"username\":" ) && ContainsString( res, "\"encoder\":" )){
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

