if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114103" );
	script_version( "2020-04-12T06:48:30+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-12 06:48:30 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2019-07-02 02:10:57 +0000 (Tue, 02 Jul 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Reolink IP Cameras Default Credentials" );
	script_dependencies( "gb_reolink_ip_cameras_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "reolink/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://support.reolink.com/hc/en-us/articles/360003516613-How-to-Reset-Bullet-or-Dome-Cameras" );
	script_tag( name: "summary", value: "The remote installation of Reolink's IP camera software is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Reolink's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Reolink's IP camera software is possible." );
	script_tag( name: "solution", value: "Change the passwords for user and admin access or enable password protection." );
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
CPE = "cpe:/h:reolink:ip_camera";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "", "admin", "admin", "admin" );
url = "/cgi-bin/api.cgi?cmd=login&token=null";
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	data = "[{\"cmd\":\"Login\",\"action\":0,\"param\":{\"User\":{\"userName\":\"" + username + "\",\"password\":\"" + password + "\"}}}]";
	req = http_post_put_req( port: port, url: url, data: data );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "\"leaseTime\"\\s*:\\s*[0-9]+," ) && IsMatchRegexp( res, "\"name\"\\s*:\\s*\"[0-9a-zA-Z]+\"" )){
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

