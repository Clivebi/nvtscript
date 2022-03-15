if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107118" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-07-15T11:10:50+0000" );
	script_tag( name: "last_modification", value: "2021-07-15 11:10:50 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-01-09 13:26:09 +0700 (Mon, 09 Jan 2017)" );
	script_name( "SonicWall / Dell SonicWALL SMA / SRA Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "SNMP based detection of SonicWall / Dell SonicWALL Secure Mobile
  Access (SMA) and Secure Remote Access (SRA) devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || !IsMatchRegexp( sysdesc, "(Dell )?SonicWALL (S[RM]A|SSL-VPN)" )){
	exit( 0 );
}
set_kb_item( name: "sonicwall/sra_sma/detected", value: TRUE );
set_kb_item( name: "sonicwall/sra_sma/snmp/port", value: port );
set_kb_item( name: "sonicwall/sra_sma/snmp/" + port + "/concluded", value: sysdesc );
product = "unknown";
version = "unknown";
series = "unknown";
prod = eregmatch( pattern: "(Dell )?SonicWALL (S[RM]A|SSL-VPN)", string: sysdesc, icase: TRUE );
if(!isnull( prod[2] )){
	product = prod[2];
}
if( IsMatchRegexp( sysdesc, "(Dell )?SonicWALL S[R|M]A Virtual Appliance" ) ){
	series = "Virtual Appliance";
	vers = eregmatch( string: sysdesc, pattern: "(Dell )?SonicWALL S[RM]A Virtual Appliance \\( ([0-9.]+[^)]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
}
else {
	vers = eregmatch( string: sysdesc, pattern: "(Dell )?SonicWALL (S[RM]A|SSL-VPN) ([0-9]+) \\(([A-Z ]+)?([^0-9]+)?([0-9.]+[^)]+)", icase: TRUE );
	if(!isnull( vers[6] )){
		version = vers[6];
	}
	if(!isnull( vers[3] )){
		series = vers[3];
	}
}
set_kb_item( name: "sonicwall/sra_sma/snmp/" + port + "/product", value: product );
set_kb_item( name: "sonicwall/sra_sma/snmp/" + port + "/series", value: series );
set_kb_item( name: "sonicwall/sra_sma/snmp/" + port + "/version", value: version );
exit( 0 );

