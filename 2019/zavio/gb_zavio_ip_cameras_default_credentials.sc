if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114096" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-05-02 12:13:25 +0200 (Thu, 02 May 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Zavio IP Cameras Default Credentials" );
	script_dependencies( "gb_zavio_ip_cameras_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zavio/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.zavio.com/downloads/product/23/QIG_F312A.pdf" );
	script_tag( name: "summary", value: "The remote installation of Zavio's IP camera software is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Zavio's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Zavio's IP camera software is possible." );
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
CPE = "cpe:/h:zavio:ip_camera";
if(!info = get_app_port_from_cpe_prefix( cpe: CPE, service: "www" )){
	exit( 0 );
}
CPE = info["cpe"];
port = info["port"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
host = http_host_name( dont_add_port: TRUE );
url = "/information.htm";
res = http_get_cache( port: port, item: url );
if( res && IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) ){
	set_kb_item( name: "www/content/auth_required", value: TRUE );
	set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: url );
	report = "It was possible to login with the following default credentials: (username:password)";
	for username in keys( creds ) {
		password = creds[username];
		req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Authorization", "Basic " + base64( str: username + ":" + password ) ) );
		res = http_keepalive_send_recv( port: port, data: req );
		if(res && ContainsString( res, "General.Network.PPPoE.Enabled&group=" ) && ContainsString( res, "var onloadFun" )){
			VULN = TRUE;
			report += "\n" + username + ":" + password;
		}
	}
}
else {
	if(res && ContainsString( res, "General.Network.PPPoE.Enabled&group=" ) && ContainsString( res, "var onloadFun" )){
		report = "The device has no password protection enabled.";
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

