if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114051" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:N" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-12-25 15:49:51 +0100 (Tue, 25 Dec 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Arecont Vision NVR Default Credentials" );
	script_dependencies( "gb_arecont_vision_nvr_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "arecont_vision/nvr/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://arecontvision.com/marketing/contents/AV_ConteraCMR_QSG.pdf" );
	script_tag( name: "summary", value: "The remote installation of Arecont Vision's NVR software is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Arecont Vision's NVR software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to the NVR is possible." );
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
CPE = "cpe:/h:arecont_vision:nvr";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin", "1234", "admin", "", "" );
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	url = "/auth.cgi";
	auth = "Basic " + base64( str: username + ":" + password );
	data = "";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Length", "0", "Authorization", auth ) );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "Content-Length: 2" ) && ContainsString( res, "OK" )){
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

