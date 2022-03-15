if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10995" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "Sun JavaServer Default Admin Password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Digital Defense Inc." );
	script_family( "Default Accounts" );
	script_dependencies( "find_service.sc", "httpver.sc", "embedded_web_server_detect.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9090 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Set the web administration interface to require a
  complex password. For more information please consult the documentation
  located in the /system/ directory of the web server." );
	script_tag( name: "summary", value: "This host is running the Sun JavaServer. This
  server has the default username and password of admin." );
	script_tag( name: "impact", value: "An attacker can use this to gain complete control
  over the web server configuration and possibly execute commands." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
url = "/servlet/admin?category=server&method=listAll&Authorization=Digest+";
url += "username%3D%22admin%22%2C+response%3D%22ae9f86d6beaa3f9ecb9a5b7e072a4138%22%2C+";
url += "nonce%3D%222b089ba7985a883ab2eddcd3539a6c94%22%2C+realm%3D%22adminRealm%22%2C+";
url += "uri%3D%22%2Fservlet%2Fadmin%22&service=";
port = http_get_port( default: 9090 );
if(http_get_is_marked_embedded( port: port )){
	exit( 0 );
}
req = NASLString( "GET ", url, " HTTP/1.0\\r\\n\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "server.javawebserver.serviceAdmin" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

