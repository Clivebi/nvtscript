if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10999" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "Linksys Router Default Password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Digital Defense Inc." );
	script_family( "Default Accounts" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Please assign the web administration
  console a difficult to guess password." );
	script_tag( name: "summary", value: "This Linksys Router has the default password
  set for the web administration console." );
	script_tag( name: "impact", value: "This console provides read/write access to the
  router's configuration. An attacker could take advantage of this to reconfigure the
  router and possibly re-route traffic." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
req = NASLString( "GET / HTTP/1.0\\r\\nAuthorization: Basic YWRtaW46YWRtaW4=\\r\\n\\r\\n" );
buf = http_send_recv( port: port, data: req );
if(ContainsString( buf, "Status.htm" ) && ContainsString( buf, "DHCP.htm" ) && ContainsString( buf, "Log.htm" ) && ContainsString( buf, "Security.htm" ) || ( ContainsString( buf, "next_file=Setup.htm" ) && ContainsString( buf, "Checking JavaScript Support" ) )){
	security_message( port: port );
}

