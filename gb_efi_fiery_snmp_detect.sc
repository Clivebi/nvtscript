if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146701" );
	script_version( "2021-09-14T08:18:57+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 08:18:57 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-13 11:59:41 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "EFI Fiery Detection Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of EFI Fiery." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( sysdesc, "^Fiery " )){
	model = "unknown";
	version = "unknown";
	set_kb_item( name: "efi/fiery/detected", value: TRUE );
	set_kb_item( name: "efi/fiery/snmp/detected", value: TRUE );
	set_kb_item( name: "efi/fiery/snmp/port", value: port );
	set_kb_item( name: "efi/fiery/snmp/" + port + "/concluded", value: sysdesc );
	set_kb_item( name: "efi/fiery/snmp/" + port + "/model", value: model );
	set_kb_item( name: "efi/fiery/snmp/" + port + "/version", value: version );
}
exit( 0 );

