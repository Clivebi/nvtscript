if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14822" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9303 );
	script_xref( name: "OSVDB", value: "3220" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "OpenBB XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "The remote host seems to be running OpenBB, a forum management system written
in PHP.

The remote version of this software is vulnerable to cross-site scripting
attacks, through the script 'board.php'.

Using a specially crafted URL, an attacker can cause arbitrary code execution
for third party users, thus resulting in a loss of integrity of their system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/openbb", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/board.php?FID=%3Cscript%3Efoo%3C/script%3E" ), port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: res )){
		security_message( port );
		exit( 0 );
	}
}
exit( 99 );

