if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140666" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 09:26:50 +0700 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Citrix Netscaler Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of Citrix Netscaler.

  This script performs SNMP based detection of Citrix Netscaler." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_xref( name: "URL", value: "https://www.citrix.com/products/netscaler-adc/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || !IsMatchRegexp( sysdesc, "^NetScaler NS" )){
	exit( 0 );
}
set_kb_item( name: "citrix_netscaler/detected", value: TRUE );
set_kb_item( name: "citrix_netscaler/snmp/detected", value: TRUE );
set_kb_item( name: "citrix_netscaler/snmp/port", value: port );
version = "unknown";
vers = eregmatch( pattern: "^NetScaler NS([0-9\\.]+): (Build (([0-9\\.]+))(.e)?.nc)?", string: sysdesc );
if(!isnull( vers[1] )){
	if( !isnull( vers[3] ) ) {
		version = vers[1] + "." + vers[3];
	}
	else {
		version = vers[1];
	}
	if(!isnull( vers[5] )){
		set_kb_item( name: "citrix_netscaler/enhanced_build", value: TRUE );
	}
	set_kb_item( name: "citrix_netscaler/snmp/" + port + "/version", value: version );
	set_kb_item( name: "citrix_netscaler/snmp/" + port + "/concluded", value: sysdesc );
}
exit( 0 );

