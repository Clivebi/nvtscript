CPE = "cpe:/h:schneider-electric:modicon_m340";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103857" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-12-16 11:44:04 +0200 (Mon, 16 Dec 2013)" );
	script_name( "Schneider Modicon M340 Default Credentials" );
	script_xref( name: "URL", value: "http://dariusfreamon.wordpress.com/2013/12/08/schneider-modicon-m340-for-ethernet-multiple-default-credentials/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_schneider_modicon_m340_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "schneider_modicon_m340/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "The remote Schneider Modicon M340 is prone to a
  default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker
  to gain access to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "It was possible to login as user 'USER' with password 'USER'." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = "/secure/embedded/http_passwd_config.htm?Language=English";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( buf, "HTTP/1\\.. 401" ) || !ContainsString( buf, "WWW-Authenticate" )){
	exit( 0 );
}
auth = base64( str: "USER:USER" );
req = ereg_replace( string: req, pattern: "\r\n\r\n", replace: "\r\nAuthorization: Basic " + auth + "\r\n\r\n\r\n" );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "HTTP/1.. 200" ) && ContainsString( buf, "<title>Passwords modification" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

