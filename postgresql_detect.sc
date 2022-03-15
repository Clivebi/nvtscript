if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100151" );
	script_version( "2020-11-12T10:09:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PostgreSQL Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/postgresql", 5432 );
	script_add_preference( name: "Postgres Username:", value: "postgres", type: "entry", id: 1 );
	script_add_preference( name: "Postgres Password:", value: "postgres", type: "password", id: 2 );
	script_xref( name: "URL", value: "https://www.postgresql.org/" );
	script_tag( name: "summary", value: "Detection of PostgreSQL, an open source object-relational
  database system.

  The script sends a connection request to the server (user:postgres, DB:postgres)
  and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
require("postgresql.inc.sc");
func check_login( user, password, port ){
	var user, password, port;
	var soc, req, res, x, len, typ, salt, userpass, pass, passlen;
	var code, sql, sqllen, slen, version;
	var concluded;
	soc = open_sock_tcp( port );
	if(!soc){
		return;
	}
	req = postgresql_create_startup_packet( user: user, db: "postgres" );
	send( socket: soc, data: req );
	res = recv( socket: soc, length: 1 );
	if(isnull( res ) || res[0] != "R"){
		close( soc );
		return;
	}
	res += recv( socket: soc, length: 4 );
	if(strlen( res ) < 5){
		close( soc );
		return;
	}
	x = substr( res, 1, 4 );
	len = ord( x[0] ) << 24 | ord( x[1] ) << 16 | ord( x[2] ) << 8 | ord( x[3] );
	res += recv( socket: soc, length: len );
	if(strlen( res ) < len || strlen( res ) < 8){
		close( soc );
		return;
	}
	typ = substr( res, strlen( res ) - 6, strlen( res ) - 5 );
	typ = ord( typ[1] );
	if(typ != 5){
		close( soc );
		return;
	}
	salt = substr( res, strlen( res ) - 4 );
	userpass = hexstr( MD5( password + user ) );
	pass = "md5" + hexstr( MD5( userpass + salt ) );
	passlen = strlen( pass ) + 5;
	req = NASLString( raw_string( 0x70 ), raw_string( ( passlen >> 24 ) & 0xff, ( passlen >> 16 ) & 0xff, ( passlen >> 8 ) & 0xff, ( passlen ) & 0xff ), pass, raw_string( 0 ) );
	send( socket: soc, data: req );
	res = recv( socket: soc, length: 1 );
	if(isnull( res ) || res[0] != "R"){
		close( soc );
		return;
	}
	res += recv( socket: soc, length: 8 );
	if(strlen( res ) < 8){
		close( soc );
		return;
	}
	code = substr( res, 5, strlen( res ) );
	if(res[0] == "R" && hexstr( code ) == "00000000"){
		recv( socket: soc, length: 65535 );
		sql = "select version();";
		sqllen = strlen( sql ) + 5;
		slen = raw_string( ( sqllen >> 24 ) & 0xff, ( sqllen >> 16 ) & 0xff, ( sqllen >> 8 ) & 0xff, ( sqllen ) & 0xff );
		req = raw_string( 0x51 ) + slen + sql + raw_string( 0x00 );
		send( socket: soc, data: req );
		res = recv( socket: soc, length: 1 );
		if(isnull( res ) || res[0] != "T"){
			close( soc );
			return;
		}
		res += recv( socket: soc, length: 1024 );
		close( soc );
		if(ContainsString( res, "PostgreSQL" ) && ContainsString( res, "SELECT" )){
			res = bin2string( ddata: res );
			version = eregmatch( pattern: "PostgreSQL (([0-9.]+)([a-z0-9.]+)?)", string: res );
			if( !isnull( version[1] ) && isnull( version[3] ) ){
				vers = version[1];
			}
			else {
				if(!isnull( version[2] ) && !isnull( version[3] )){
					vers = version[2] + "." + version[3];
				}
			}
		}
		if(vers){
			concluded = res;
			return vers;
		}
	}
	close( soc );
	return;
}
port = service_get_port( default: 5432, proto: "postgresql" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = postgresql_create_startup_packet( user: "postgres", db: "postgres" );
send( socket: soc, data: req );
res = recv( socket: soc, length: 256 );
close( soc );
if(!res || !IsMatchRegexp( res[0], "[ER]" )){
	exit( 0 );
}
dump = bin2string( ddata: res, noprint_replacement: " " );
concluded = chomp( hexdump( ddata: res ) );
b = substr( res, 1, 4 );
blen = ord( b[0] ) / 24 | ord( b[1] ) / 16 | ord( b[2] ) / 8 | ord( b[3] );
if(( dump[0] == "E" && ( ContainsString( dump, "ERROR" ) || ContainsString( dump, "FATAL" ) || ContainsString( dump, "PANIC" ) || ContainsString( dump, "WARNING" ) || ContainsString( dump, "NOTICE" ) || ContainsString( dump, "DEBUG" ) || ContainsString( dump, "INFO" ) || ContainsString( dump, "LOG" ) ) ) || ( dump[0] == "R" && ( blen == 8 || blen == 12 ) )){
	if(dump[0] == "R"){
		version = eregmatch( pattern: "server_version (([0-9.]+)([a-z0-9.]+)?)", string: dump );
		if(version){
			concluded = version[0];
		}
		if( !isnull( version[1] ) && isnull( version[3] ) ) {
			vers = version[1];
		}
		else {
			if(!isnull( version[2] ) && !isnull( version[3] )){
				vers = version[2] + "." + version[3];
			}
		}
		if(isnull( vers )){
			login = script_get_preference( name: "Postgres Username:", id: 1 );
			if(!login){
				login = "postgres";
			}
			password = script_get_preference( name: "Postgres Password:", id: 2 );
			if(!password){
				password = "postgres";
			}
			vers = check_login( user: login, password: password, port: port );
		}
		if(!isnull( vers )){
			set_kb_item( name: "PostgreSQL/Remote/" + port + "/Ver", value: vers );
			set_kb_item( name: "OpenDatabase/found", value: TRUE );
		}
	}
	service_register( port: port, proto: "postgresql" );
	if( !isnull( vers ) ){
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:postgresql:postgresql:" );
	}
	else {
		cpe = "cpe:/a:postgresql:postgresql";
		vers = "unknown";
	}
	install = port + "/tcp";
	register_product( cpe: cpe, location: install, port: port, service: "postgresql" );
	set_kb_item( name: "postgresql/detected", value: TRUE );
	log_message( port: port, data: build_detection_report( app: "PostgreSQL", version: vers, install: install, cpe: cpe, concluded: concluded ) );
}
exit( 0 );

