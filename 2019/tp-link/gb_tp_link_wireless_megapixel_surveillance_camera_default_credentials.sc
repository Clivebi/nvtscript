if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114078" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-02-27 14:35:18 +0100 (Wed, 27 Feb 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "TP-Link Megapixel Surveillance Camera Default Credentials" );
	script_dependencies( "gb_tp_link_wireless_megapixel_surveillance_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "tp-link/wireless/megapixel_surveillance_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://static.tp-link.com/resources/document/TL-SC3430N_V1_User_Guide_1910010550.pdf" );
	script_tag( name: "summary", value: "The remote installation of TP-Link's Megapixel surveillance camera software is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of TP-Link's Megapixel surveillance camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to TP-Link's Megapixel surveillance camera software is possible." );
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
CPE = "cpe:/h:tp-link:megapixel_surveillance_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url = "/cgi-bin/admin/param?action=list&group=General.Brand.ProdFullName&group=Properties.Firmware.Version";
for cred in keys( creds ) {
	req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Authorization", "Basic " + base64( str: cred + ":" + creds[cred] ) ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "root.General.Brand.ProdFullName=Wireless" ) && ContainsString( res, "root.Properties.Firmware.Version=" )){
		VULN = TRUE;
		report += "\n" + cred + ":" + creds[cred];
		version = eregmatch( pattern: "root.Properties.Firmware.Version=([a-zA-Z0-9._]+)", string: res, icase: TRUE );
		if(!isnull( version[1] )){
			set_kb_item( name: "tp-link/wireless/megapixel_surveillance_camera/version", value: version[1] );
		}
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials (username:password): " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

