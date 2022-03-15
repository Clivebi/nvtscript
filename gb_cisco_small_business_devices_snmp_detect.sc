if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105767" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-06-16 09:06:38 +0200 (Thu, 16 Jun 2016)" );
	script_name( "Cisco Small Business Device Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Cisco Small Business devices." );
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
if(!IsMatchRegexp( sysdesc, "^Linux[^,]*, Cisco Small Business" )){
	exit( 0 );
}
cpe = "cpe:/h:cisco:small_business";
vers = "unknown";
m = eregmatch( pattern: "Cisco Small Business ([a-zA-z]+[^, ]+)", string: sysdesc );
if(!isnull( m[1] )){
	model = m[1];
	set_kb_item( name: "cisco/small_business/model", value: model );
}
version = eregmatch( pattern: ", Version ([0-9]+[^ \r\n]+)", string: sysdesc );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "cisco/small_business/version", value: vers );
}
register_product( cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
report = build_detection_report( app: "Cisco Small Business " + model, version: vers, install: port + "/udp", cpe: cpe, concluded: sysdesc );
log_message( port: port, data: report, proto: "udp" );
exit( 0 );

