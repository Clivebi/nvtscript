if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114092" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-04-23 12:30:09 +0200 (Tue, 23 Apr 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Foscam IP Camera Default Credentials" );
	script_dependencies( "gb_foscam_ip_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 88 );
	script_mandatory_keys( "foscam/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.certiology.com/computing/router-login/foscam-default-password.html" );
	script_tag( name: "summary", value: "The remote installation of Foscam's IP camera software is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Foscam's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Foscam's IP camera software is possible." );
	script_tag( name: "solution", value: "Change the credentials for the affected users." );
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
require("url_func.inc.sc");
CPE = "cpe:/h:foscam:ip_camera";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin", "", "admin" );
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	url = "/cgi-bin/CGIProxy.fcgi?" + urlencode( str: "usr=" + username + "&pwd=" + password + "&cmd=logIn&usrName=" + username + "&pwd=" + password, uppercase: TRUE );
	req = http_get_req( port: port, url: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<logInResult>0</logInResult>" )){
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

