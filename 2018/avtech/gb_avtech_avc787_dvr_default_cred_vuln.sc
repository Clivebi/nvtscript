if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813818" );
	script_version( "2021-06-22T05:51:37+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-22 05:51:37 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-07 12:34:02 +0530 (Tue, 07 Aug 2018)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "AVTech AVC 787 DVR Web Interface Default Credentials Vulnerability" );
	script_tag( name: "summary", value: "This host is running an AVTech AVC 787 DVR
  device and is prone to a default account authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Sends crafted data via an HTTP POST request
  and checks whether it is possible to login or not." );
	script_tag( name: "insight", value: "The web interface for the AVTech AVC 787 DVR is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials." );
	script_tag( name: "impact", value: "Successful exploitation would allow a remote attacker
  to bypass authentication and launch further attacks." );
	script_tag( name: "affected", value: "All AVTech AVC 787 DVR devices." );
	script_tag( name: "solution", value: "Change the passwords for user and admin access." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://www.avtech.hk/english/products5_1_787.htm" );
	script_xref( name: "URL", value: "http://www.praetorianprefect.com/2009/12/shodan-cracking-ip-surveillance-dvr" );
	script_xref( name: "URL", value: "http://www.smartvisiondirect.com/doc/avtech_avc_series_security_dvr_networking_howto_guide.pdf" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_dependencies( "gb_avtech_avc7xx_dvr_device_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "avtech/avc7xx/dvr/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("url_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
CPE = "cpe:/o:avtech:avc7xx_dvr_firmware";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "admin", "admin" );
url = "/home.cgi";
hostType = get_kb_item( "avtech/avc7xx/dvr/host_type" );
for cred in keys( creds ) {
	if( hostType == "SQ_Webcam" ){
		url = "/home.htm";
		data = "username=" + cred + "&password=" + creds[cred] + "&Submit=Submit";
	}
	else {
		if( hostType == "Video_Web_Server" ){
			baseURL = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
			data = "username=" + cred + "&password=" + creds[cred] + "&url=" + urlencode( str: baseURL, uppercase: TRUE ) + "&Submit=Submit";
		}
		else {
			exit( 0 );
		}
	}
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "---\\s*Video Web Server\\s*---" )){
		VULN = TRUE;
		if(!password){
			password = "<no/empty password>";
		}
		report += "\n" + cred + ":" + creds[cred];
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials (username:password):\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

