if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141825" );
	script_version( "2021-09-03T14:39:52+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 14:39:52 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-04 13:53:28 +0700 (Fri, 04 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Xerox Printer Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of Xerox printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	exit( 0 );
}
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^(FUJI )?(Xerox|XEROX)" )){
	set_kb_item( name: "xerox/printer/detected", value: TRUE );
	set_kb_item( name: "xerox/printer/snmp/detected", value: TRUE );
	set_kb_item( name: "xerox/printer/snmp/port", value: port );
	set_kb_item( name: "xerox/printer/snmp/" + port + "/concluded", value: sysdesc );
	mod = eregmatch( pattern: "(Xerox|FUJI XEROX) ([^;]+)", string: sysdesc );
	if(!isnull( mod[2] )){
		set_kb_item( name: "xerox/printer/snmp/" + port + "/model", value: mod[2] );
	}
	vers = eregmatch( pattern: "SS ([0-9.]+),", string: sysdesc );
	if( !isnull( vers[1] ) ){
		set_kb_item( name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1] );
	}
	else {
		vers = eregmatch( pattern: "System Software ([0-9.]+),", string: sysdesc );
		if( !isnull( vers[1] ) ){
			set_kb_item( name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1] );
		}
		else {
			vers = eregmatch( pattern: "ESS( )?([0-9.]+),", string: sysdesc );
			if(!isnull( vers[2] )){
				set_kb_item( name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[2] );
			}
		}
	}
	exit( 0 );
}
exit( 0 );

