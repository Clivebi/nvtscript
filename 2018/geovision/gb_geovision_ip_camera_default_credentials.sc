if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114036" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-09-28 11:55:31 +0200 (Fri, 28 Sep 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "GeoVision IP Camera Default Credentials" );
	script_dependencies( "gb_geovision_ip_camera_remote_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "geovision/ip_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/blog/tag/default-password-axis/" );
	script_tag( name: "summary", value: "The remote installation of GeoVision IP Camera is prone to
  a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of GeoVision IP Camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to GeoVision IP Camera is possible." );
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
CPE = "cpe:/h:geovision:geovisionip_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url1 = "/ssi.cgi/Login.htm";
url2 = "/LoginPC.cgi";
for cred in keys( creds ) {
	req1 = http_get_req( port: port, url: url1, add_headers: make_array( "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ) );
	res1 = http_keepalive_send_recv( port: port, data: req1 );
	info = eregmatch( pattern: "var cc1=\"([^\"]+)\"; var cc2=\"([^\"]+)\";", string: res1 );
	if(isnull( info[1] ) || isnull( info[2] )){
		continue;
	}
	cc1 = info[1];
	cc2 = info[2];
	umd5 = toupper( hexstr( MD5( NASLString( cc1, tolower( cred ), cc2 ) ) ) );
	pmd5 = toupper( hexstr( MD5( NASLString( cc2, tolower( creds[cred] ), cc1 ) ) ) );
	data = "username=&password=&Apply=Apply&umd5=" + umd5 + "&pmd5=" + pmd5 + "&browser=1&is_check_OCX_OK=0";
	req2 = http_post_put_req( port: port, url: url2, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language", "en-US,en;q=0.5", "Content-Type", "application/x-www-form-urlencoded" ) );
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(ContainsString( res2, "IsAdmId() {return 1;}" )){
		VULN = TRUE;
		report += "\nusername: \"" + cred + "\", password: \"" + creds[cred] + "\"";
		cid = eregmatch( pattern: "CLIENT_ID=([0-9]+)", string: res2 );
		if(isnull( cid[1] )){
			set_kb_item( name: "geovision/ip_camera/client_id", value: cid[1] );
		}
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

