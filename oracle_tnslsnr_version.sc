if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10658" );
	script_version( "2020-11-20T06:21:12+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-20 06:21:12 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Oracle Database Detection (TNS service)" );
	script_tag( name: "summary", value: "Detects the installed version of an Oracle Database.

  This script sends 'CONNECT_DATA=(COMMAND=VERSION)' command via Oracle
  tnslsnr, a network interface to the remote Oracle database and try to get
  the version from the response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 James W. Abendschan <jwa@jammed.com>" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 1521, 1527 );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
func tnscmd( sock, command ){
	var sock, command;
	var command_length, packet_length, plen_h, plen_l, clen_h, clen_l, packet;
	command_length = strlen( command );
	packet_length = command_length + 58;
	plen_h = packet_length / 256;
	plen_l = 256 * plen_h;
	plen_l = packet_length - plen_h;
	clen_h = command_length / 256;
	clen_l = 256 * clen_h;
	clen_l = command_length - clen_l;
	packet = raw_string( plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, command );
	send( socket: sock, data: packet );
}
func extract_version( socket, port ){
	var socket, port;
	var header, report, tot_len, remaining, rest, flags, version;
	header = recv( socket: socket, length: 8, timeout: 5 );
	if(strlen( header ) < 5){
		return 0;
	}
	if(ord( header[4] ) == 4){
		report = NASLString( "A TNS service is running on this port but it\\n", "refused to honor an attempt to connect to it.\\n", "(The TNS reply code was ", ord( header[4] ), ")" );
		service_register( port: port, proto: "oracle_tnslsnr" );
		log_message( port: port, data: report );
		return 0;
	}
	if(ord( header[4] ) != 2){
		return 0;
	}
	tot_len = getword( blob: header );
	remaining = tot_len - 8;
	if(remaining < 0){
		return 0;
	}
	rest = recv( socket: socket, length: remaining, timeout: 5 );
	header = recv( socket: socket, length: 8, timeout: 5 );
	if(strlen( header ) < 5 || ord( header[4] ) != 6){
		return 0;
	}
	tot_len = getword( blob: header );
	remaining = tot_len - 8;
	if(remaining < 0){
		return 0;
	}
	flags = recv( socket: socket, length: 2, timeout: 5 );
	version = recv( socket: socket, length: remaining - 2, timeout: 5 );
	return version;
}
func oracle_version( port ){
	var port;
	var sock, cmd, version, ver, cpe;
	sock = open_sock_tcp( port );
	if(sock){
		cmd = "(CONNECT_DATA=(COMMAND=VERSION))";
		tnscmd( sock: sock, command: cmd );
		version = extract_version( socket: sock, port: port );
		close( sock );
		if(version == 0){
			return 0;
		}
		ver = eregmatch( pattern: "Version ([0-9.]+)", string: version );
		if(isnull( ver[1] )){
			return 0;
		}
		service_register( port: port, proto: "oracle_tnslsnr" );
		set_kb_item( name: "OracleDatabaseServer/installed", value: TRUE );
		set_kb_item( name: "oracle_tnslsnr/" + port + "/version", value: version );
		set_kb_item( name: "OpenDatabase/found", value: TRUE );
		set_kb_item( name: "oracle/tnslsnr_or_application_server/detected", value: TRUE );
		cpe = build_cpe( value: ver[1], exp: "^([0-9.]+)", base: "cpe:/a:oracle:database_server:" );
		if(!cpe){
			cpe = "cpe:/a:oracle:database_server";
		}
		register_product( cpe: cpe, location: port + "/tcp", port: port, service: "oracle_tnslsnr" );
		log_message( data: build_detection_report( app: "Oracle Database Server", version: ver[1], install: port + "/tcp", cpe: cpe, concluded: ver[0] ), port: port );
	}
}
ports = unknownservice_get_ports( default_port_list: make_list( 1521,
	 1527 ) );
for port in ports {
	oracle_version( port: port );
}
exit( 0 );

