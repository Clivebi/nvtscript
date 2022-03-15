if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106560" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-02-03 09:38:09 +0700 (Fri, 03 Feb 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Honeywell Excel Web Detection (BACnet)" );
	script_tag( name: "summary", value: "BACnet based detection of Honeywell Excel Web." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_bacnet_detect.sc" );
	script_mandatory_keys( "bacnet/vendor", "bacnet/model_name" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( nodefault: TRUE, ipproto: "udp", proto: "bacnet" );
vendor = get_kb_item( "bacnet/vendor" );
if(!vendor || !ContainsString( vendor, "Honeywell" )){
	exit( 0 );
}
mod = get_kb_item( "bacnet/model_name" );
if(!mod || !ContainsString( mod, "Excel Web" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "honeywell/excel_web/detected", value: TRUE );
set_kb_item( name: "honeywell/excel_web/bacnet/port", value: port );
fw = get_kb_item( "bacnet/firmware" );
if(fw){
	vers = eregmatch( pattern: "XLWebExe-([0-9-]+)", string: fw );
	if(!isnull( vers[1] )){
		version = ereg_replace( pattern: "-", string: vers[1], replace: "." );
		set_kb_item( name: "honeywell/excel_web/bacnet/" + port + "/concluded", value: fw );
	}
}
set_kb_item( name: "honeywell/excel_web/bacnet/" + port + "/version", value: version );
exit( 0 );

