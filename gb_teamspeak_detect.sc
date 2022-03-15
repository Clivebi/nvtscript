if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100681" );
	script_version( "2020-11-12T13:45:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 13:45:39 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "TeamSpeak 2/3 Server Detection (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/teamspeak-serverquery", 10011, "Services/teamspeak-tcpquery", 51234, 30033 );
	script_tag( name: "summary", value: "This host is running a TeamSpeak 2/3 Server. TeamSpeak is proprietary Voice over IP
  software that allows users to speak on a chat channel with other users, much like a telephone conference call." );
	script_xref( name: "URL", value: "http://www.teamspeak.com/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
sport = service_get_ports( default_port_list: make_list( 10011 ), proto: "teamspeak-serverquery" );
tport = service_get_ports( default_port_list: make_list( 51234 ), proto: "teamspeak-tcpquery" );
for port in make_list( sport,
	 tport ) {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	buf = recv( socket: soc, length: 16 );
	if(isnull( buf ) && !ContainsString( buf, "[TS]" ) && !ContainsString( buf, "TS3" )){
		close( soc );
		continue;
	}
	send( socket: soc, data: "version\n" );
	buf = recv( socket: soc, length: 256 );
	vers = "unknown";
	install = port + "/tcp";
	if( ContainsString( buf, "version" ) && ContainsString( buf, "msg" ) ){
		version = eregmatch( pattern: "version=([^ ]+) (build=([^ ]+))*", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
		}
		if(!isnull( version[3] )){
			vers += " build=" + version[3];
		}
		service = "teamspeak-serverquery";
		service_register( port: port, proto: service );
		app = "TeamSpeak 3 Server";
		set_kb_item( name: "teamspeak3_server/" + port, value: vers );
		set_kb_item( name: "teamspeak3_server/detected", value: TRUE );
		cpe = "cpe:/a:teamspeak:teamspeak3";
	}
	else {
		send( socket: soc, data: "ver\n" );
		buf = recv( socket: soc, length: 256 );
		version = eregmatch( pattern: "([0-9.]+)", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
		}
		service = "teamspeak-tcpquery";
		service_register( port: port, proto: service );
		app = "TeamSpeak 2 Server";
		set_kb_item( name: "teamspeak2_server/" + port, value: vers );
		set_kb_item( name: "teamspeak2_server/detected", value: TRUE );
		cpe = "cpe:/a:teamspeak:teamspeak2";
	}
	close( soc );
	cpe2 = build_cpe( value: version[1], exp: "^([0-9.]+)(-[0-9a-zA-Z]+)?", base: cpe + ":" );
	cpe2 = str_replace( string: cpe2, find: "-", replace: "" );
	if( isnull( cpe2 ) ) {
		cpe2 = cpe + ":::server";
	}
	else {
		cpe2 = cpe2 + "::server";
	}
	register_product( cpe: cpe2, location: install, port: port, service: service );
	log_message( data: build_detection_report( app: app, version: version[1], install: install, cpe: cpe2, concluded: version[0] ), port: port );
}
if("teamspeak3_server/detected"){
	port = 30033;
	if(!get_port_state( port )){
		exit( 0 );
	}
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	service_register( port: port, proto: "teamspeak-filetransfer", message: "A TS3 file transfer service seems to be running on this port" );
	log_message( port: port, data: "A TS3 file transfer service seems to be running on this port" );
	close( soc );
}
exit( 0 );

