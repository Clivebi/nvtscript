CPE = "cpe:/a:apache:axis2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111006" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 44055 );
	script_cve_id( "CVE-2010-0219" );
	script_name( "Apache Axis2 axis2-admin default credentials" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2015-03-18 08:00:00 +0100 (Wed, 18 Mar 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "gb_apache_axis2_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8080, 8081 );
	script_mandatory_keys( "axis2/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Apache Axi2 web interface is prone to a default account
  authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information, modify system configuration or execute code by uploading
  malicious webservices." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials: admin/axis2" );
	script_tag( name: "solution", value: "Change the password." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44055" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15869" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
useragent = http_get_user_agent();
data = NASLString( "userName=admin&password=axis2&submit=+Login+" );
len = strlen( data );
req = "POST " + dir + "/axis2-admin/login HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Welcome to Axis2 Web Admin Module !!" )){
	security_message( port: port );
	exit( 0 );
}
url = NASLString( dir, "/adminlogin?userName=admin&password=axis2&submit=+Login++" );
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
cookie = eregmatch( pattern: "JSESSIONID=([0-9a-zA-Z]+);", string: res );
if(isnull( cookie[1] )){
	exit( 0 );
}
req = "GET " + dir + "/admin.jsp HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Cookie: JSESSIONID=" + cookie[1] + "\r\n" + "\r\n";
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Welcome to the Axis2 administration system!" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

