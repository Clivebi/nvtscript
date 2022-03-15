if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12069" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "SMC2804WBR Default Password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Audun Larsen" );
	script_family( "Default Accounts" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the administrator password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "The remote host is a SMC2804WBR access point.

  This host is installed with a default administrator
  password (smcadmin) which has not been modified." );
	script_tag( name: "impact", value: "An attacker may exploit this flaw to gain control over
  this host using the default password." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/", port: port );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "SMC2804WBR" ) && ContainsString( res, "Please enter correct password for Administrator Access. Thank you." )){
	host = http_host_name( port: port );
	variables = NASLString( "page=login&pws=smcadmin" );
	req = NASLString( "POST /login.htm HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(!buf){
		exit( 0 );
	}
	if(!ContainsString( buf, "<title>LOGIN</title>" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

