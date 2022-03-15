if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106411" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-25 11:50:20 +0700 (Fri, 25 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HP Comware Devices Detect (SSH)" );
	script_tag( name: "summary", value: "This script performs SSH based detection of HP Comware Devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/hp/comware/detected" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner || !IsMatchRegexp( banner, "SSH-[0-9.]+-Comware" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "Comware-([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "hp/comware_device/version", value: version );
}
set_kb_item( name: "hp/comware_device", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:comware:" );
if(!cpe){
	cpe = "cpe:/a:hp:comware";
}
register_product( cpe: cpe, port: port, service: "ssh" );
log_message( data: build_detection_report( app: "HP Comware Device", version: version, cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

