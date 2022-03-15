if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108310" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-07 08:03:31 +0100 (Thu, 07 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NETGEAR ProSAFE Devices Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/netgear/prosafe/detected" );
	script_tag( name: "summary", value: "This script performs Telnet based detection of NETGEAR ProSAFE devices." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "User:" ) && ( ContainsString( banner, "(GSM7224V2)" ) || ContainsString( banner, "(GSM7224)" ) )){
	model = "unknown";
	fw_version = "unknown";
	fw_build = "unknown";
	mod = eregmatch( pattern: "\\(([0-9a-zA-Z\\\\-]+)\\)", string: banner, icase: TRUE );
	if(mod[1]){
		model = mod[1];
		set_kb_item( name: "netgear/prosafe/telnet/" + port + "/concluded", value: mod[0] );
	}
	set_kb_item( name: "netgear/prosafe/telnet/" + port + "/model", value: model );
	set_kb_item( name: "netgear/prosafe/telnet/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "netgear/prosafe/telnet/" + port + "/fw_build", value: fw_build );
	set_kb_item( name: "netgear/prosafe/telnet/detected", value: TRUE );
	set_kb_item( name: "netgear/prosafe/telnet/port", value: port );
	set_kb_item( name: "netgear/prosafe/detected", value: TRUE );
}
exit( 0 );

