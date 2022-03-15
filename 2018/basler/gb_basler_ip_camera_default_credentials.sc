if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114030" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-09-10 12:59:11 +0200 (Mon, 10 Sep 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Basler IP Camera Default Credentials" );
	script_dependencies( "gb_basler_ip_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "basler/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://ipvm.com/reports/ip-cameras-default-passwords-directory" );
	script_tag( name: "summary", value: "The remote Basler IP Camera is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Basler IP Camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Basler IP Camera is possible." );
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
CPE = "cpe:/a:basler:ip_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
username = "admin";
password = "admin";
url = "/cgi-bin/auth_if.cgi?Login";
data = "Auth.Username=" + username + "&Auth.Password=" + password;
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "success: true" ) && ContainsString( res, "errorcode: 0" )){
	report = "It was possible to login via the default username \"" + username + "\" and the default password \"" + password + "\".";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

