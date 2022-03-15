if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140043" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-11-02 15:29:27 +0100 (Wed, 02 Nov 2016)" );
	script_name( "Cisco (Acano) Meeting Server Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Cisco Meeting Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(!IsMatchRegexp( sysdesc, "^(Cisco Meeting|Acano) Server [0-9.]+$" )){
	exit( 0 );
}
set_kb_item( name: "cisco/meeting_server/installed", value: TRUE );
cpe = "cpe:/a:cisco:meeting_server";
vers = "unknown";
version = eregmatch( pattern: "^(Cisco Meeting|Acano) Server ([0-9.]+)$", string: sysdesc );
if(!isnull( version[2] )){
	vers = version[2];
	cpe += ":" + vers;
	set_kb_item( name: "cisco/meeting_server/version", value: vers );
}
register_product( cpe: cpe, location: "161/udp", port: port, service: "snmp", proto: "udp" );
report = build_detection_report( app: "Cisco (Acano) Meeting Server", version: vers, install: "161/udp", cpe: cpe, concluded: sysdesc );
log_message( port: port, data: report, proto: "udp" );
exit( 0 );

