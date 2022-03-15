if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108518" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-12-12 18:08:58 +0100 (Wed, 12 Dec 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Logitech SqueezeCenter/Media Server CLI Detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "find_service4.sc" );
	script_require_ports( "Services/squeezecenter_cli", "9090" );
	script_tag( name: "summary", value: "The script tries to identify services supporting
  Logitech SqueezeCenter/Media Server CLI interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 9090, proto: "squeezecenter_cli" );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
send( socket: soc, data: "serverstatus\r\n" );
res = recv( socket: soc, length: 512 );
close( soc );
if(!res || !ContainsString( res, "serverstatus" )){
	exit( 0 );
}
if(egrep( string: res, pattern: "^serverstatus\\s+", icase: FALSE ) && ( ContainsString( res, " lastscan%3A" ) || ContainsString( res, " version%3A" ) || ContainsString( res, " uuid%3A" ) || ContainsString( res, "player%20count%3A" ) ) && ( ContainsString( res, " info%20total%20albums%3A" ) || ContainsString( res, " info%20total%20artists%3A" ) || ContainsString( res, " info%20total%20genres%3A" ) || ContainsString( res, " info%20total%20songs%3A" ) )){
	res = chomp( res );
	version = "unknown";
	vers = eregmatch( string: res, pattern: "version%3A([0-9.]+) ", icase: FALSE );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "logitech/squeezecenter/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/cli/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/cli/port", value: port );
	set_kb_item( name: "logitech/squeezecenter/cli/" + port + "/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/cli/" + port + "/version", value: version );
	set_kb_item( name: "logitech/squeezecenter/cli/" + port + "/concluded", value: res );
	log_message( port: port, data: "A service supporting the Logitech SqueezeCenter/Media Server CLI interface seems to be running on this port." );
	service_register( port: port, proto: "squeezecenter_cli", message: "A service supporting the Logitech SqueezeCenter/Media Server CLI interface seems to be running on this port." );
}
exit( 0 );

