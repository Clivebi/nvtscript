if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114066" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-02-05 15:30:18 +0100 (Tue, 05 Feb 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Samsung iPolis Default Credentials" );
	script_dependencies( "gb_samsung_ipolis_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "samsung/ipolis/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://www.a1securitycameras.com/technical-support/default-username-passwords-ip-addresses-for-surveillance-cameras/" );
	script_tag( name: "summary", value: "The remote installation of Samsung iPolis is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Samsung iPolis is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Samsung iPolis is possible." );
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
CPE = "cpe:/a:samsung:ipolis";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "4321" );
url = "/home/monitoring.cgi";
for cred in keys( creds ) {
	req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	info = eregmatch( pattern: "Digest realm=\"([^\"]+)\", nonce=\"([0-9a-zA-Z]+)\",", string: res );
	if(isnull( info[1] ) || isnull( info[2] )){
		continue;
	}
	realm = info[1];
	nonce = info[2];
	cnonce = rand_str( charset: "abcdefghijklmnopqrstuvwxyz0123456789", length: 16 );
	qop = "auth";
	nc = "00000001";
	ha1 = hexstr( MD5( NASLString( cred, ":", realm, ":", creds[cred] ) ) );
	ha2 = hexstr( MD5( NASLString( "GET:", url ) ) );
	response = hexstr( MD5( NASLString( ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2 ) ) );
	auth = "Digest username=\"" + cred + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + url + "\", response=\"" + response + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";
	req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Authorization", auth ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "var model" ) && ContainsString( res, "var devicePort" )){
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

