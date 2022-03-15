CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13644" );
	script_version( "2021-02-25T13:36:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Apache HTTP Server 'mod_rootme' Backdoor" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Malware" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "embedded_web_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_tag( name: "solution", value: "- Remove the mod_rootme module from httpd.conf/modules.conf

  - Consider reinstalling the computer, as it is likely to have been compromised by an intruder" );
	script_tag( name: "summary", value: "The remote system appears to be running the mod_rootme module,
  this module silently allows a user to gain a root shell access to the machine via HTTP requests." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Apache" )){
	exit( 0 );
}
if(http_get_is_marked_embedded( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: NASLString( "GET root HTTP/1.0\\n", "Host: ", host, "\\r\\n" ) );
sleep( 1 );
send( socket: soc, data: NASLString( "\\n" ) );
sleep( 1 );
res_vx = recv( socket: soc, length: 1024 );
if(!res_vx){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: NASLString( "id\\r\\n", "Host: ", host, "\\r\\n" ) );
res = recv( socket: soc, length: 1024 );
if(!res){
	close( soc );
	exit( 0 );
}
if(ereg( pattern: "^uid=[0-9]+\\(root\\)", string: res ) && ereg( pattern: "^rootme-[0-9].[0-9] ready", string: res_vx )){
	send( socket: soc, data: NASLString( "exit\\r\\n", "Host: ", host, "\\r\\n" ) );
	close( soc );
	security_message( port: port );
	exit( 0 );
}
close( soc );
exit( 99 );

