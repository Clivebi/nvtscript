if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105163" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "F5 Networks BIG-IP Webinterface Default Credentials" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2015-01-09 16:30:36 +0100 (Fri, 09 Jan 2015)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_f5_big_ip_webinterface_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "f5/big_ip/web_management/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote F5 BIG-IP web interface is prone to a default account authentication
  bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials: admin/admin" );
	script_tag( name: "solution", value: "Change the password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
port = get_kb_item( "f5/big_ip/web_management/port" );
if(!port){
	exit( 0 );
}
pd = "username=admin&passwd=admin";
req = http_post( port: port, item: "/tmui/logmein.html", data: pd );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "BIGIPAuthCookie" ) && ContainsString( res, "BIGIPAuthUsernameCookie" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

