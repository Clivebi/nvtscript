if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802883" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-07-09 11:16:49 +0530 (Mon, 09 Jul 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Symantec pcAnywhere Access Server Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 5631 );
	script_tag( name: "summary", value: "Detection of Symantec pcAnywhere Access Server.

  The script sends a connection request to the server and attempts to
  extract the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
pcAnyport = unknownservice_get_port( default: 5631 );
soc = open_sock_tcp( pcAnyport );
if(!soc){
	exit( 0 );
}
initial = raw_string( 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: initial );
pcanydata = recv( socket: soc, length: 1024 );
close( soc );
sleep( 3 );
if(!pcanydata){
	exit( 0 );
}
if(ContainsString( pcanydata, "The Symantec pcAnywhere Access Server does not support" ) || ContainsString( pcanydata, "Please press <Enter>..." ) || ContainsString( hexstr( pcanydata ), "1b593200010342000001001" )){
	set_kb_item( name: "Symantec/pcAnywhere-server/Installed", value: TRUE );
	cpe = "cpe:/a:symantec:pcanywhere";
	service_register( port: pcAnyport, ipproto: "tcp", proto: "pcanywheredata" );
	register_product( cpe: cpe, location: pcAnyport + "/tcp", port: pcAnyport );
	log_message( data: build_detection_report( app: "Symantec pcAnywhere Access Server", version: "Unknown", install: pcAnyport + "/tcp", cpe: cpe, concluded: "Unknown" ), port: pcAnyport );
	exit( 0 );
}

