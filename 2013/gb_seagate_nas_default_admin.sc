CPE_PREFIX = "cpe:/o:seagate:blackarmor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103754" );
	script_version( "2021-07-21T11:54:38+0000" );
	script_tag( name: "last_modification", value: "2021-07-21 11:54:38 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-08-08 14:02:06 +0200 (Thu, 08 Aug 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "Seagate NAS Default Login (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_seagate_blackarmor_nas_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "seagate/blackarmor_nas/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Seagate NAS is prone to a default account
  authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with admin/admin" );
	script_tag( name: "insight", value: "It was possible to login with username 'admin' and password
  'admin'." );
	script_tag( name: "solution", value: "Change the password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( port: port, cpe: cpe, nofork: TRUE )){
	exit( 0 );
}
url = "/index.php";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>Seagate NAS" ) || !ContainsString( buf, "Set-Cookie" )){
	exit( 0 );
}
co = eregmatch( pattern: "Set-Cookie: ([^\n\r]+)", string: buf );
if(isnull( co[1] )){
	exit( 0 );
}
cookie = co[1];
useragent = http_get_user_agent();
host = http_host_name( port: port );
data = "p_user=admin&p_pass=admin&lang=en&xx=1&loginnow=Login";
len = strlen( data );
req = "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Referer: http://" + host + "/?lang=en\r\n" + "DNT: 1\r\n" + "Cookie: " + cookie + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
http_send_recv( port: port, data: req, bodyonly: FALSE );
req = "GET /admin/system_status.php?lang=en&gi=sy002 HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Referer: http://" + host + "/?lang=en\r\n" + "DNT: 1\r\n" + "Cookie: " + cookie + "\r\n" + "\r\n";
buf = http_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( buf, ">Logout<" ) && ContainsString( buf, ">System Status<" ) && ContainsString( buf, "Admin Password" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

