if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17304" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6671 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-1135", "CVE-1999-0571" );
	script_name( "Default web account on Zyxel" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "ZyXEL-RomPager/banner" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password immediately." );
	script_tag( name: "summary", value: "The remote host is a Zyxel router with its default password set." );
	script_tag( name: "impact", value: "An attacker could connect to the web interface and reconfigure it." );
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
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "ZyXEL-RomPager" )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] +401 " )){
	exit( 0 );
}
req = http_get_req( port: port, url: "/", add_headers: make_array( "Authorization", "Basic YWRtaW46MTIzNA==" ) );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] +200 " )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

