if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105532" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-01-27 10:46:32 +0100 (Wed, 27 Jan 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cisco IOS XR Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ios_xr_detect_snmp.sc", "gb_cisco_ios_xr_version_ssh.sc" );
	script_mandatory_keys( "cisco_ios_xr/detected" );
	script_tag( name: "summary", value: "This script get the version of Cisco IOS XR detected via SSH or SNMP" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
source = "ssh";
version = get_kb_item( "cisco_ios_xr/" + source + "/version" );
if(!version){
	source = "snmp";
	version = get_kb_item( "cisco_ios_xr/" + source + "/version" );
	if(!version){
		exit( 0 );
	}
}
set_kb_item( name: "cisco/ios_xr/version", value: version );
set_kb_item( name: "cisco/ios_xr/detection_source", value: source );
model = get_kb_item( "cisco_ios_xr/" + source + "/model" );
if(model){
	set_kb_item( name: "cisco/ios_xr/model", value: model );
}
cpe = "cpe:/o:cisco:ios_xr:" + version;
register_product( cpe: cpe, location: source );
os_register_and_report( os: "Cisco IOS XR", cpe: cpe, banner_type: toupper( source ), desc: "Cisco IOS XR Version Detection", runs_key: "unixoide" );
log_message( data: build_detection_report( app: "Cisco IOS XR", version: version, install: source, cpe: cpe, concluded: source ), port: 0 );
exit( 0 );

