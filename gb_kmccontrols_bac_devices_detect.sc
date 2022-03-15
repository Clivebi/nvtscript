if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106128" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-12 10:36:40 +0700 (Tue, 12 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "KMC Controls BAC Devices Detection" );
	script_tag( name: "summary", value: "Detection of KMC Controls BAC-Devices

Tries to detect KMC Controls BAC devices over the BACnet protocol." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_bacnet_detect.sc" );
	script_mandatory_keys( "bacnet/vendor", "bacnet/model_name" );
	script_xref( name: "URL", value: "http://www.kmccontrols.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
vendor = get_kb_item( "bacnet/vendor" );
if(!vendor || !ContainsString( vendor, "KMC Controls Inc" )){
	exit( 0 );
}
model = get_kb_item( "bacnet/model_name" );
if(!model || !IsMatchRegexp( model, "^BAC-" )){
	exit( 0 );
}
fw_version = "unknown";
version = get_kb_item( "bacnet/firmware" );
ver = eregmatch( pattern: "([A-Z][0-9.]+)", string: version );
if(!isnull( ver[1] )){
	fw_version = ver[1];
}
set_kb_item( name: "kmc_controls_bac/detected", value: TRUE );
set_kb_item( name: "kmc_controls_bac/model", value: model );
if(fw_version != "unknown"){
	set_kb_item( name: "kmc_controls_bac/fw_version", value: fw_version );
}
cpe = build_cpe( value: fw_version, exp: "([0-9.]+)", base: "cpe:/h:kmc_controls:" + tolower( model ) + ":" );
if(isnull( cpe )){
	cpe = "cpe:/h:kmc_controls:" + tolower( model );
}
register_product( cpe: cpe, port: 47808, service: "bacnet", proto: "udp" );
log_message( data: build_detection_report( app: "KMC Controls " + model, version: fw_version, install: "47808/udp", cpe: cpe, concluded: version ), port: 47808, proto: "udp" );
exit( 0 );

