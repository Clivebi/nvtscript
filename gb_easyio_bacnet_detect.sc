if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106502" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-01-09 11:19:19 +0700 (Mon, 09 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "EasyIO Detection (BACNET)" );
	script_tag( name: "summary", value: "Detection of EasyIO Devices

Tries to detect EasyIO devices over the BACnet protocol." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_bacnet_detect.sc" );
	script_mandatory_keys( "bacnet/vendor", "bacnet/model_name" );
	script_xref( name: "URL", value: "https://www.easyio.eu/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
vendor = get_kb_item( "bacnet/vendor" );
if(!vendor || !ContainsString( vendor, "EasyIO" )){
	exit( 0 );
}
mod = get_kb_item( "bacnet/model_name" );
if(!mod){
	exit( 0 );
}
mod = eregmatch( pattern: "([^\\/]+)", string: mod );
if(isnull( mod[1] )){
	exit( 0 );
}
model = mod[1];
sw_version = "unknown";
fw_version = "unknown";
sw = get_kb_item( "bacnet/application_sw" );
if(sw){
	sw_version = sw;
	set_kb_item( name: "easyio/sw_version", value: sw_version );
}
fw = get_kb_item( "bacnet/firmware" );
if(fw){
	fw_version = fw;
	set_kb_item( name: "easyio/fw_version", value: fw_version );
}
set_kb_item( name: "easyio/installed", value: TRUE );
cpe = build_cpe( value: fw_version, exp: "^([0-9.]+)", base: "cpe:/a:easyio:easyio:" );
if(!cpe){
	cpe = "cpe:/a:easyio:easyio";
}
register_product( cpe: cpe, port: 47808, service: "bacnet", proto: "udp" );
log_message( data: build_detection_report( app: "EasyIO " + model, version: fw_version, install: "47808/udp", cpe: cpe, concluded: fw, extra: "Application Version: " + sw_version ), port: 47808, proto: "udp" );
exit( 0 );

