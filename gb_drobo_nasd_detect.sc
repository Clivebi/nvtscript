if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142077" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-03-06 10:14:54 +0700 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drobo NASd Detection" );
	script_tag( name: "summary", value: "Detection of Drobo NASd.

The script sends a connection request to the server and attempts to detect Drobo NASd." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 5000 );
	exit( 0 );
}
require("dump.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = unknownservice_get_port( default: 5000 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
res = recv( socket: soc, length: 9096 );
if(!res){
	exit( 0 );
}
res = bin2string( ddata: res, noprint_replacement: "" );
if(ContainsString( res, "<ESATMUpdate>" ) && ContainsString( res, "DRINASD" )){
	set_kb_item( name: "drobo/nas/detected", value: TRUE );
	set_kb_item( name: "drobo/nasd/detected", value: TRUE );
	set_kb_item( name: "drobo/nasd/port", value: port );
	model = eregmatch( pattern: "<mModel>([^<]+)", string: res );
	if(!isnull( model[1] )){
		set_kb_item( name: "drobo/nasd/model", value: model[1] );
	}
	version = eregmatch( pattern: "<mVersion>([^<]+)", string: res );
	if(!isnull( version[1] )){
		version = str_replace( string: version[1], find: " ", replace: "" );
		version = str_replace( string: version, find: "[", replace: "." );
		version = str_replace( string: version, find: "]", replace: "" );
		version = str_replace( string: version, find: "-", replace: "." );
		set_kb_item( name: "drobo/nasd/fw_version", value: version );
	}
	esaid = eregmatch( pattern: "<mESAID>([^<]+)", string: res );
	if(!isnull( esaid[1] )){
		set_kb_item( name: "drobo/nasd/esaid", value: esaid[1] );
	}
	service_register( port: port, proto: "drobo-nasd" );
}
exit( 0 );

