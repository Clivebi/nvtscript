if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112138" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-11-23 11:04:05 +0100 (Thu, 23 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "SNMP based detection of the Greenbone Security Manager (GSM) / Greenbone OS (GOS)." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("snmp_func.inc.sc");
require("misc_func.inc.sc");
port = snmp_get_port( default: 161 );
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Greenbone Security Manager" )){
	oid = snmp_get( port: port, oid: "1.3.6.1.2.1.1.5.0" );
	set_kb_item( name: "greenbone/gos/detected", value: TRUE );
	set_kb_item( name: "greenbone/gos/snmp/detected", value: TRUE );
	set_kb_item( name: "greenbone/gos/snmp/port", value: port );
	type_nd_vers = eregmatch( pattern: "^([0-9]+|TRIAL|DEMO|ONE|MAVEN|150V|EXPO|25V|CE|CENO|DECA|TERA|PETA|EXA)-([0-9\\-]+)", string: oid );
	if(!isnull( type_nd_vers[1] )){
		gsm_type = type_nd_vers[1];
		set_kb_item( name: "greenbone/gsm/snmp/" + port + "/type", value: gsm_type );
	}
	if( !isnull( type_nd_vers[2] ) ){
		gos_ver = str_replace( string: type_nd_vers[2], find: "-", replace: "." );
		set_kb_item( name: "greenbone/gos/snmp/" + port + "/version", value: gos_ver );
		set_kb_item( name: "greenbone/gos/snmp/" + port + "/concluded", value: oid );
		set_kb_item( name: "greenbone/gos/snmp/" + port + "/concludedOID", value: "1.3.6.1.2.1.1.5.0" );
	}
	else {
		set_kb_item( name: "greenbone/gos/snmp/" + port + "/concluded", value: sysdesc );
	}
}
exit( 0 );

