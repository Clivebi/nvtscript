if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140629" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cambium Networks cnPilot Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of Cambium Networks cnPilot.

  This script performs SNMP based detection of Cambium Networks cnPilot." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_xref( name: "URL", value: "https://www.cambiumnetworks.com/products/wifi/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || !IsMatchRegexp( sysdesc, "^cnPilot" )){
	exit( 0 );
}
set_kb_item( name: "cambium_cnpilot/detected", value: TRUE );
set_kb_item( name: "cambium_cnpilot/snmp/detected", value: TRUE );
set_kb_item( name: "cambium_cnpilot/snmp/port", value: port );
model = "unknown";
fw_version = "unknown";
mod = eregmatch( pattern: "cnPilot ([^ ]+)", string: sysdesc );
if(!isnull( mod[1] )){
	model = mod[1];
	set_kb_item( name: "cambium_cnpilot/snmp/" + port + "/model", value: model );
}
vers = eregmatch( pattern: "cnPilot " + model + " ([0-9.]+-R.*)", string: sysdesc );
if(!isnull( vers[1] )){
	fw_version = vers[1];
	set_kb_item( name: "cambium_cnpilot/snmp/" + port + "/fw_version", value: fw_version );
}
exit( 0 );

