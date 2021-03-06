CPE = "cpe:/h:siemens:gigaset:sx762";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103730" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2013-06-05 14:44:04 +0200 (Wed, 05 Jun 2013)" );
	script_name( "Siemens Gigaset sx762 Default Password" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_gigaset_sx762_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "gigaset_sx762/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "The remote Siemens Gigaset sx762 is prone to a default account authentication
  bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to
  gain access to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "It was possible to login with password 'admin'." );
	script_tag( name: "qod_type", value: "remote_vul" );
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
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
login = "form_submission_type=login&form_submission_parameter=&current_page=welcome_login.html";
login += "&next_page=home_security.html&i=1&admin_role_name=administrator&operator_role_name=operator";
login += "&subscriber_role_name=subscriber&choose_role=0&your_password=admin&Login=OK";
len = strlen( login );
req = NASLString( "POST /UE/ProcessForm HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\\r\\n", "Accept-Encoding: identity\\r\\n", "DNT: 1\\r\\n", "Connection: close\\r\\n", "Referer: http://", host, ":", port, "/UE/welcome_login.html\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", login );
result = http_send_recv( port: port, data: req, bodyonly: FALSE );
url = "/UE/advanced.html";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "Log Off" ) && ContainsString( buf, "security.html" ) && ContainsString( buf, "status.html" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

