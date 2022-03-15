if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11004" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "WhatsUp Gold Default Admin Account" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 Digital Defense Inc." );
	script_family( "Default Accounts" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Login to this system and either disable the admin
  account or assign it a difficult to guess password." );
	script_tag( name: "summary", value: "This WhatsUp Gold server still has the default password for
  the admin user account. An attacker can use this account to probe other systems on the network
  and obtain sensitive information about the monitored systems." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
req = NASLString( "GET / HTTP/1.0\\r\\nAuthorization: Basic YWRtaW46YWRtaW4K\\r\\n\\r\\n" );
res = http_send_recv( port: port, data: req );
if(ContainsString( buf, "Whatsup Gold" ) && !ContainsString( buf, "Unauthorized User" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

