CPE_PREFIX = "cpe:/o:linksys:";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80070" );
	script_version( "2020-09-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-09-08 08:34:44 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_xref( name: "OSVDB", value: "821" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Linksys Router Default Account (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_linksys_devices_consolidation.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "linksys/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Connect to this port with a web browser, and click on the 'Password'
  section to set a strong password." );
	script_tag( name: "summary", value: "The remote Linksys device has its default account (no username / 'admin') set." );
	script_tag( name: "impact", value: "An attacker may connect to it and reconfigure it using this account." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
req = http_get( item: "/", port: port );
req -= NASLString( "\\r\\n\\r\\n" );
req += NASLString( "\\r\\nAuthorization: Basic OmFkbWlu\\r\\n\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!res){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

