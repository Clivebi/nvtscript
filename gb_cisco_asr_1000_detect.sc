if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105342" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-09-01 15:55:24 +0200 (Tue, 01 Sep 2015)" );
	script_name( "Cisco ASR 1000 Router Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Cisco ASR 1000 Router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!ContainsString( sysdesc, "Cisco IOS Software, ASR1000 Software" )){
	exit( 0 );
}
set_kb_item( name: "cisco_asr_1000/installed", value: TRUE );
cpe = "cpe:/h:cisco:asr_1000";
vers = "unknown";
version = eregmatch( pattern: "Version ([^,]+),", string: sysdesc );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp" );
log_message( data: build_detection_report( app: "Cisco ASR1000", version: vers, install: port + "/snmp", cpe: cpe, concluded: sysdesc ), port: port, proto: "udp" );
exit( 0 );

