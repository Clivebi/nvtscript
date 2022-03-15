if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108447" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-07-03 15:09:21 +0200 (Tue, 03 Jul 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Android Debug Bridge (ADB) Protocol Detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "5555" );
	script_tag( name: "summary", value: "The script tries to identify services supporting
  the Android Debug Bridge (ADB) Protocol." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = 5555;
if(!get_port_state( port )){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
req = "CNXN";
req += raw_string( 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32, 0x02, 0x00, 0x00, 0xbc, 0xb1, 0xa7, 0xb1 );
req += "host::";
req += raw_string( 0x00 );
send( socket: soc, data: req );
res = recv( socket: soc, length: 512 );
close( soc );
if(strlen( res ) < 33){
	exit( 0 );
}
hexres = hexstr( res );
strres = bin2string( ddata: res, noprint_replacement: " " );
authpattern = "^415554480[1-3]0000000000000014000000";
authpattern += "....0000beaaabb7................";
authpattern += "........................$";
cnxnpattern = "^434e584e0000000100100000..000000....0000bcb1a7b1";
if( eregmatch( string: hexres, pattern: authpattern ) ){
	found = TRUE;
	reqauth = TRUE;
	extra = "\nAuthentication is required.";
}
else {
	if( eregmatch( string: hexres, pattern: cnxnpattern ) && infos = eregmatch( string: strres, pattern: "ro\\.product\\.name=([^;]+);ro\\.product\\.model=([^;]+);ro\\.product\\.device=([^;]+);(features=([^\\0x00]+))?" ) ){
		found = TRUE;
		reqauth = FALSE;
		noauth = TRUE;
		extra = "\nNo Authentication is required. Collected device info:\n\n";
		extra += "Product name:   " + infos[1] + "\n";
		extra += "Product model:  " + infos[2] + "\n";
		extra += "Product device: " + infos[3];
		if(infos[5]){
			extra += "\nFeatures:       " + infos[5];
		}
	}
	else {
		if(eregmatch( string: hexres, pattern: cnxnpattern ) && IsMatchRegexp( strres, "(bootloader|device|host):.*:" )){
			found = TRUE;
			reqauth = FALSE;
			noauth = TRUE;
			extra = "\nNo Authentication is required.";
		}
	}
}
if(found){
	cpe = "cpe:/o:google:android";
	install = port + "/tcp";
	version = "unknown";
	set_kb_item( name: "adb/" + port + "/version", value: version );
	set_kb_item( name: "adb/" + port + "/detected", value: TRUE );
	set_kb_item( name: "adb/detected", value: TRUE );
	if(noauth){
		set_kb_item( name: "adb/" + port + "/noauth", value: TRUE );
		set_kb_item( name: "adb/noauth", value: TRUE );
	}
	if(reqauth){
		set_kb_item( name: "adb/" + port + "/reqauth", value: TRUE );
		set_kb_item( name: "adb/reqauth", value: TRUE );
	}
	service_register( port: port, proto: "adb" );
	register_product( cpe: cpe, location: install, port: port );
	os_register_and_report( os: "Android", cpe: cpe, desc: "Android Debug Bridge (ADB) Protocol Detection", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Android Debug Bridge (ADB) Protocol", version: version, install: install, extra: extra, concluded: strres, cpe: cpe ), port: port );
}
exit( 0 );

