if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100243" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ZNC Detection (IRC)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc", "gb_znc_http_detect.sc" );
	script_require_ports( "Services/irc", "Services/www", 6667, 6697 );
	script_tag( name: "summary", value: "IRC based detection ZNC." );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
ports = make_list();
irc_ports = service_get_ports( default_port_list: make_list( 6667,
	 6697 ), proto: "irc" );
if(irc_ports){
	ports = make_list( ports,
		 irc_ports );
}
http_ports = service_get_ports( default_port_list: make_list( 6667,
	 6697 ), proto: "www" );
if(http_ports){
	for http_port in http_ports {
		res = http_get_cache( port: http_port, item: "/" );
		if(!get_kb_item( "znc/http/" + http_port + "/detected" ) && !ContainsString( res, "Web Access is not enabled" )){
			continue;
		}
		ports = make_list( ports,
			 http_port );
	}
}
ports = nasl_make_list_unique( ports );
for port in ports {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	req = NASLString( "USER\\r\\n" );
	send( socket: soc, data: req );
	buf = recv_line( socket: soc, length: 64 );
	close( soc );
	if(egrep( pattern: "irc\\.znc\\.in NOTICE AUTH", string: buf, icase: TRUE ) || ( ContainsString( buf, "irc.znc.in" ) && ContainsString( buf, "Password required" ) )){
		version = "unknown";
		service_register( port: port, proto: "irc", message: "An IRC server seems to be running on this port." );
		set_kb_item( name: "znc/detected", value: TRUE );
		set_kb_item( name: "znc/irc/detected", value: TRUE );
		set_kb_item( name: "znc/irc/port", value: port );
		set_kb_item( name: "znc/irc/" + port + "/detected", value: TRUE );
		set_kb_item( name: "znc/irc/" + port + "/version", value: version );
		set_kb_item( name: "znc/irc/" + port + "/concluded", value: chomp( buf ) );
	}
}
exit( 0 );

