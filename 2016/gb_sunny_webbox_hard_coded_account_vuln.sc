CPE = "cpe:/o:sma_solar_technology_ag:webbox_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808204" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-3964" );
	script_bugtraq_id( 76617 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-24 10:37:42 +0530 (Tue, 24 May 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Sunny WebBox Hard-Coded Account Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Sunny WebBox
  and is prone to Hard-Coded Account vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP POST and
  check whether it is able to login or not." );
	script_tag( name: "insight", value: "The flaw is due to:
  it was possible to login with hard-coded passwords 'User:0000'
  or 'Installer:1111' that cannot be changed or disabled by a user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain full access to the system." );
	script_tag( name: "affected", value: "Sunny WebBox All versions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://files.sma.de/dl/8584/Sicherheit-TEN103010.pdf" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-15-181-02A" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_sunny_webbox_remote_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "Sunny/WebBox/Installed" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!sunnyPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: sunnyPort, cpe: CPE )){
	exit( 0 );
}
credentials = make_list( "User:0000",
	 "Installer:1111" );
url = "/culture/index.dml";
host = http_host_name( port: sunnyPort );
for credential in credentials {
	user_pass = split( buffer: credential, sep: ":", keep: FALSE );
	user = chomp( user_pass[0] );
	pass = chomp( user_pass[1] );
	data = NASLString( "LangEN&" + "Userlevels=" + user + "&password=" + pass );
	len = strlen( data );
	req = "POST /culture/login HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: sunnyPort, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "name=\"Sunny WebBox" ) && ContainsString( res, "Logout" ) && ContainsString( res, "name=\"My Plant" ) && ( ContainsString( res, "title=\"Settings" ) || ContainsString( res, "title=\"Spot Values" ) || ContainsString( res, "title=\"Updates" ) )){
		report = http_report_vuln_url( port: sunnyPort, url: "/culture/login" );
		report = report + "\n\nIt was possible to login using the following credentials:\n\n" + user + ":" + pass + "\n";
		security_message( port: sunnyPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

