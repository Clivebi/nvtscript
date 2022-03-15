CPE = "cpe:/a:nuuo:nuuo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112328" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-07-17 11:26:00 +0200 (Tue, 17 Jul 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2016-6553" );
	script_bugtraq_id( 93807 );
	script_name( "NUUO Network Video Recorder Devices Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_nuuo_devices_web_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8081 );
	script_mandatory_keys( "nuuo/web/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Nuuo has released an update to address the issue. Please see the vendor information.

  As a general good security practice, only allow trusted hosts to connect to the device.
  Use of strong, unique passwords can help reduce the efficacy of brute force password guessing attacks." );
	script_tag( name: "summary", value: "NUUO Network Video Recorder devices have default credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
cookie = get_kb_item( "nuuo/web/cookie" );
if(isnull( cookie )){
	exit( 0 );
}
req = http_get( port: port, item: "/" );
res = http_keepalive_send_recv( port: port, data: req );
cookie_match = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: res );
if( cookie_match[1] ){
	cookie = cookie_match[1];
}
else {
	exit( 0 );
}
vuln = FALSE;
report = "";
credentials = make_list( "admin:admin",
	 "localdisplay:111111" );
useragent = http_get_user_agent();
host = http_host_name( port: port );
for credential in credentials {
	user_pass = split( buffer: credential, sep: ":", keep: FALSE );
	user = chomp( user_pass[0] );
	pass = chomp( user_pass[1] );
	if(tolower( pass ) == "none"){
		pass = "";
	}
	data = NASLString( "language=en&user=" + user + "&pass=" + pass + "&submit=Login" );
	len = strlen( data );
	req = "POST /login.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Referer: http://" + host + "/login.php/\r\n" + "Cookie: " + cookie + "\r\n" + "Connection: keep-alive\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( res, "HTTP/1.. 302" ) && ContainsString( res, "/setting.php" )){
		req = "GET /setting.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Referer: http://" + host + "/setting.php\r\n" + "Cookie: " + cookie + "\r\n" + "Connection: keep-alive\r\n" + "\r\n";
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "<span class=\"productName\">" ) || ContainsString( res, "<div id=\"official_fw_ver\">" )){
			vuln = TRUE;
			report += "It was possible to login into the NUUO Network Video Recorder Administration at " + http_report_vuln_url( port: port, url: "/login.php", url_only: TRUE ) + " using user \"" + user + "\" with password \"" + pass + "\".\r\n";
			product_match = eregmatch( pattern: "<span class=\"productName\">([A-Z0-9-]+)</span>", string: res );
			if(product_match[1]){
				product = product_match[1];
			}
		}
	}
}
if(product){
	set_kb_item( name: "nuuo/model", value: product );
	report += "\r\nThe running device is a NUUO " + product + ".";
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
