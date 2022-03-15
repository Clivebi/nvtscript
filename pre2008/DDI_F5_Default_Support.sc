if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10820" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "F5 Device Default Support Password (HTTP)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2001 Digital Defense Inc." );
	script_family( "Default Accounts" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Remove the support account entirely or
  change the password of this account to something that is difficult to guess." );
	script_tag( name: "summary", value: "This F5 Networks system still has the default
  password set for the support user account. This account normally provides read/write
  access to the web configuration utility." );
	script_tag( name: "impact", value: "An attacker could take advantage of this to reconfigure
  your systems and possibly gain shell access to the system with super-user privileges." );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
req = NASLString( "GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\\r\\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\\r\\n\\r\\n" );
buf = http_send_recv( port: port, data: req );
if(( ContainsString( buf, "/bigipgui/" ) ) && ( ContainsString( buf, "System Command" ) )){
	security_message( port: port );
}

