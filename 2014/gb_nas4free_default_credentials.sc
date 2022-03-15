if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105055" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "nas4free Default Admin Credentials" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2014-07-02 12:02:06 +0200 (Wed, 02 Jul 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_nas4free_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "nas4free/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote nas4free web interface is prone to a default
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
CPE = "cpe:/a:nas4free:nas4free";
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = "/login.php";
postData = "username=admin&password=nas4free";
useragent = http_get_user_agent();
len = strlen( postData );
host = http_host_name( port: port );
req = "POST /login.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept-Encoding: identity\r\n" + "Referer: http://" + host + "/login.php" + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + postData;
result = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( result, "HTTP/1.1 302" ) && ContainsString( result, "index.php" )){
	co = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: result );
	if(isnull( co[1] )){
		exit( 99 );
	}
	req = "GET /index.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Cookie: " + co[1] + "\r\n\r\n";
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "system.php" ) && ContainsString( buf, "logout.php" )){
		report = "It was possible to login with user \"admin\" and password \"nas4free\".";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

