if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111060" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Zebra PrintServer Webinterface Default Password" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-25 11:00:00 +0100 (Wed, 25 Nov 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Zebra PrintServer Webinterface is
  prone to a default account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "vuldetect", value: "Try to login with a default password." );
	script_tag( name: "insight", value: "It was possible to login with default password 1234" );
	script_tag( name: "solution", value: "Change the password." );
	script_xref( name: "URL", value: "https://support.zebra.com/cpws/docs/znet2/ps_firm/znt2_pwd.html" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/settings", port: port );
if(ContainsString( res, "Zebra Technologies" ) || ContainsString( res, "Internal Wired PrintServer" ) || ContainsString( res, "ENTER PASSWORD" )){
	vuln = 0;
	host = http_host_name( port: port );
	report = "";
	useragent = http_get_user_agent();
	data = NASLString( "0=1234" );
	len = strlen( data );
	req = "POST /authorize HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "Access Granted. This IP Address now has admin" ) && ContainsString( res, "access to the restricted printer pages." )){
		security_message( port: port, data: "It was possible to login using the following password:\\n\\n1234" );
		exit( 0 );
	}
}
exit( 99 );

