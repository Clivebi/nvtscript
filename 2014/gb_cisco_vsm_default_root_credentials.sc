CPE = "cpe:/a:cisco:video_surveillance_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103896" );
	script_version( "2020-05-11T13:25:52+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Cisco Video Surveillance Manager Default Root Credentials" );
	script_tag( name: "last_modification", value: "2020-05-11 13:25:52 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "creation_date", value: "2014-01-28 15:02:06 +0200 (Tue, 28 Jan 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_video_surveillance_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cisco_video_surveillance_manager/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Cisco Video Surveillance Manager is prone to a default
  account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = "GET /config/password.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n";
buf = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
userpass = base64( str: "root:secur4u" );
req += "Authorization: Basic " + userpass + "\r\n\r\n";
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<title>Management Console Password" )){
	report = "It was possible to access \"/config/password.php\" by using the following credentials:\n\nroot:secur4u";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

