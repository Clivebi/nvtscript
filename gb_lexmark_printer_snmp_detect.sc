if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142834" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2019-09-03 01:48:27 +0000 (Tue, 03 Sep 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Lexmark Printer Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Lexmark printer devices." );
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
if(IsMatchRegexp( sysdesc, "^Lexmark" )){
	set_kb_item( name: "lexmark_printer/detected", value: TRUE );
	set_kb_item( name: "lexmark_printer/snmp/detected", value: TRUE );
	set_kb_item( name: "lexmark_printer/snmp/port", value: port );
	set_kb_item( name: "lexmark_printer/snmp/" + port + "/concluded", value: sysdesc );
	model = eregmatch( pattern: "Lexmark ([^ ]+)", string: sysdesc );
	if(!isnull( model[1] )){
		set_kb_item( name: "lexmark_printer/snmp/" + port + "/model", value: model[1] );
	}
	version = eregmatch( pattern: "version ([^ ]+)", string: sysdesc );
	if(!isnull( version[1] ) && !IsMatchRegexp( version[1], "^N" )){
		set_kb_item( name: "lexmark_printer/snmp/" + port + "/fw_version", value: version[1] );
	}
}
exit( 0 );

