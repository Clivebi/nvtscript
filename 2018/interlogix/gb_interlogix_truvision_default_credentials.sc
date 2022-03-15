if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114057" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-12-28 17:07:10 +0100 (Fri, 28 Dec 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Interlogix TruVision Default Credentials" );
	script_dependencies( "gb_interlogix_truvision_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "interlogix/truvision/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://static.interlogix.com/library/1072627A%20TruVision%20IP%20Camera%20Configuration%20Manual.pdf" );
	script_tag( name: "summary", value: "The remote installation of TruVision is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of TruVision is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login is possible." );
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
CPE = "cpe:/a:interlogix:truvision";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "1234" );
for cred in keys( creds ) {
	url = "/Login.htm";
	data = "command=login&username=" + cred + "&password=" + creds[cred];
	auth = "NetSuveillanceWebCookie=%7B%22username%22%3A%22" + cred + "%22%7D";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Cookie", auth ) );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "var g_SoftWareVersion=" ) && ContainsString( res, "var g_HardWareVersion=" )){
		VULN = TRUE;
		report += "\nusername: \"" + cred + "\", password: \"" + creds[cred] + "\"";
		ver = eregmatch( pattern: "var g_SoftWareVersion=\"V([0-9.a-zA-Z]+)\";", string: res );
		if(!isnull( ver[1] )){
			set_kb_item( name: "interlogix/truvision/version", value: ver[1] );
		}
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

