if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114032" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-09-12 13:07:54 +0200 (Wed, 12 Sep 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Canon Network Camera Default Credentials" );
	script_dependencies( "gb_canon_network_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "canon/network_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://ipvm.com/reports/ip-cameras-default-passwords-directory" );
	script_tag( name: "summary", value: "The remote Canon Network Camera is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Canon Network Camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Canon Network Camera is possible." );
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
CPE = "cpe:/a:canon:network_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "root", "camera" );
url = "/admin/network.html";
for cred in keys( creds ) {
	auth_header = make_array( "Authorization", "Basic " + base64( str: cred + ":" + creds[cred] ) );
	req = http_get_req( port: port, url: url, add_headers: auth_header );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "Administrator Password" ) && ContainsString( res, "Password</label>" )){
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

