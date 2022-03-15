if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103844" );
	script_version( "2020-12-28T14:44:29+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2020-12-28 14:44:29 +0000 (Mon, 28 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-12-02 13:58:18 +0100 (Mon, 02 Dec 2013)" );
	script_name( "Redis Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service1.sc" );
	script_require_ports( "Services/redis", 6379 );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
cpe = "cpe:/a:redis:redis";
app = "Redis Server";
port = service_get_port( default: 6379, proto: "redis" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
install = port + "/tcp";
send( socket: soc, data: "PING\r\n" );
recv = recv( socket: soc, length: 32 );
if( IsMatchRegexp( recv, "^\\-NOAUTH" ) ){
	send( socket: soc, data: "AUTH foobared\r\n" );
	recv = recv( socket: soc, length: 32 );
	if(ContainsString( recv, "-ERR invalid password" )){
		close( soc );
		set_kb_item( name: "redis/installed", value: TRUE );
		service_register( port: port, proto: "redis" );
		register_and_report_cpe( app: app, concluded: recv, cpename: cpe, insloc: install, regPort: port, extra: "The Redis server is protected by a password." );
		exit( 0 );
	}
	set_kb_item( name: "redis/" + port + "/default_password", value: TRUE );
	set_kb_item( name: "redis/default_password", value: TRUE );
	extra = "Redis Server is protected with the default password 'foobared'.";
}
else {
	if( ContainsString( recv, "-DENIED Redis is running in prot" ) ){
		close( soc );
		set_kb_item( name: "redis/installed", value: TRUE );
		service_register( port: port, proto: "redis" );
		register_and_report_cpe( app: app, concluded: recv, cpename: cpe, insloc: install, regPort: port, extra: "The Redis server is running in protected mode." );
		set_kb_item( name: "redis/" + port + "/protected_mode", value: TRUE );
		set_kb_item( name: "redis/protected_mode", value: TRUE );
		exit( 0 );
	}
	else {
		if(IsMatchRegexp( recv, "^\\+?PONG" ) || ContainsString( recv, "-MISCONF Redis is configured to " )){
			if(ContainsString( recv, "-MISCONF Redis is configured to" )){
				recv_line( socket: soc, length: 2048 );
			}
			send( socket: soc, data: "AUTH openvas\r\n" );
			recv = recv( socket: soc, length: 64 );
			if(ContainsString( recv, "-ERR Client sent AUTH, but no password is set" )){
				set_kb_item( name: "redis/" + port + "/no_password", value: TRUE );
				set_kb_item( name: "redis/no_password", value: TRUE );
				extra = "Redis Server is not protected with a password.";
			}
		}
	}
}
send( socket: soc, data: "info\r\n" );
recv = recv( socket: soc, length: 1024 );
close( soc );
if(!ContainsString( recv, "redis_version" )){
	exit( 0 );
}
set_kb_item( name: "redis/installed", value: TRUE );
rv = "unknown";
redis_version = eregmatch( pattern: "redis_version:([^\r\n]+)", string: recv );
if(!isnull( redis_version[1] )){
	set_kb_item( name: "redis/" + port + "/version", value: redis_version[1] );
	rv = redis_version[1];
	cpe += ":" + rv;
}
service_register( port: port, proto: "redis" );
register_product( cpe: cpe, location: install, port: port, proto: "tcp" );
log_message( data: build_detection_report( app: app, version: rv, install: install, cpe: cpe, concluded: redis_version[0], extra: extra ), port: port );
exit( 0 );

