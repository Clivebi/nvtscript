CPE_PREFIX = "cpe:/h:brickcom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114059" );
	script_version( "2021-06-30T10:23:57+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 10:23:57 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-01-03 19:42:47 +0100 (Thu, 03 Jan 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Brickcom Network Camera Default Credentials (HTTP)" );
	script_dependencies( "gb_brickcom_network_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "brickcom/network_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://www.brickcom.com/support/faq_contents.php?id=48" );
	script_tag( name: "summary", value: "The remote Brickcom IP camera is using known default credentials
  for the HTTP login." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Brickcom's IP camera software is lacking a
  proper password configuration, which makes critical information and actions accessible for people
  with knowledge of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks via HTTP if a successful login to the IP camera
  software is possible." );
	script_tag( name: "solution", value: "Change the password." );
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
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url = "/";
for username in keys( creds ) {
	password = creds[username];
	auth = "Basic " + base64( str: username + ":" + password );
	req = http_get_req( port: port, url: url, add_headers: make_array( "Authorization", auth ) );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "var stateMenu;" ) || ContainsString( res, "var viewer=" ) || ContainsString( res, "var DeviceProductName=" )){
		VULN = TRUE;
		report += "\nusername: \"" + username + "\", password: \"" + password + "\"";
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report + "\n\n";
	report += http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

