if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900923" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Foxit WAC Server Detection (Telnet + SSH)" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22, "Services/telnet", 23 );
	script_mandatory_keys( "ssh_or_telnet/foxit/wac-server/detected" );
	script_tag( name: "summary", value: "This script finds the version of Foxit WAC Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
func set_detection( port, banner, service ){
	var port, banner, service;
	var cpe;
	set_kb_item( name: "Foxit-WAC-Server/installed", value: TRUE );
	install = port + "/tcp";
	version = "unknown";
	vers = eregmatch( pattern: "(Foxit-WAC-Server-|WAC Server )(([0-9.]+).?(([a-zA-Z]+[ 0-9]+))?)", string: banner );
	if(!isnull( vers[2] )){
		version = ereg_replace( pattern: " ", string: vers[2], replace: "." );
		version = ereg_replace( pattern: "\\.Build", string: version, replace: "" );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:foxitsoftware:wac_server:" );
	if(!cpe){
		cpe = "cpe:/a:foxitsoftware:wac_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: service );
	log_message( data: build_detection_report( app: "Foxit WAC Server", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
}
telnetPorts = telnet_get_ports();
for port in telnetPorts {
	banner = telnet_get_banner( port: port );
	if(banner && ContainsString( banner, "WAC" ) && ContainsString( banner, "Foxit Software" )){
		set_detection( port: port, banner: banner, service: "telnet" );
	}
}
sshdPort = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: sshdPort );
if(!banner || !ContainsString( banner, "Foxit-WAC-Server" )){
	exit( 0 );
}
set_detection( port: sshdPort, banner: banner, service: "ssh" );
exit( 0 );

