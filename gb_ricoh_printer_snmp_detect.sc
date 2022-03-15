if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142806" );
	script_version( "2021-09-10T13:20:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 13:20:55 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 08:44:37 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "RICOH Printer Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of RICOH printer devices." );
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
if(IsMatchRegexp( sysdesc, "^RICOH" ) && ( ContainsString( sysdesc, "RICOH Network Printer" ) || egrep( pattern: "^RICOH Pro", string: sysdesc, icase: TRUE ) )){
	model = "unknown";
	version = "unknown";
	set_kb_item( name: "ricoh/printer/detected", value: TRUE );
	set_kb_item( name: "ricoh/printer/snmp/detected", value: TRUE );
	set_kb_item( name: "ricoh/printer/snmp/port", value: port );
	set_kb_item( name: "ricoh/printer/snmp/" + port + "/concluded", value: sysdesc );
	vers = eregmatch( pattern: "RICOH ((Aficio |Pro)?([A-Z]+)? [^ ]+)( V?([0-9.]+))?", string: sysdesc );
	if(!isnull( vers[1] )){
		model = vers[1];
	}
	if(!isnull( vers[5] )){
		version = vers[5];
	}
	set_kb_item( name: "ricoh/printer/snmp/" + port + "/model", value: model );
	set_kb_item( name: "ricoh/printer/snmp/" + port + "/fw_version", value: version );
}
exit( 0 );

