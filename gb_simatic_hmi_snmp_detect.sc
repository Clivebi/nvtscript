if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141682" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-11-14 13:52:50 +0700 (Wed, 14 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens SIMATIC HMI Device Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Siemens SIMATIC HMI devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(ContainsString( sysdesc, "Siemens, SIMATIC HMI" )){
	set_kb_item( name: "simatic_hmi/detected", value: TRUE );
	set_kb_item( name: "simatic_hmi/snmp/detected", value: TRUE );
	set_kb_item( name: "simatic_hmi/snmp/port", value: port );
	set_kb_item( name: "simatic_hmi/snmp/" + port + "/concluded", value: sysdesc );
	sp = split( buffer: sysdesc, sep: ",", keep: FALSE );
	if(!isnull( sp[2] )){
		model = eregmatch( pattern: "^ ([^ ]+ ?(Basic|Comfort)?)", string: sp[2] );
		if(!isnull( model[1] )){
			set_kb_item( name: "simatic_hmi/snmp/" + port + "/model", value: model[1] );
		}
	}
	if(!isnull( sp[5] )){
		version = eregmatch( pattern: "SW: V ([0-9 ]+)", string: sp[5] );
		if( !isnull( version[1] ) ){
			version = str_replace( string: version[1], find: " ", replace: "." );
			set_kb_item( name: "simatic_hmi/snmp/" + port + "/fw_version", value: version );
		}
		else {
			version = eregmatch( pattern: "FW:V([0-9.]+)", string: sp[5] );
			if(!isnull( version[1] )){
				set_kb_item( name: "simatic_hmi/snmp/" + port + "/fw_version", value: version[1] );
			}
		}
	}
	if(!isnull( sp[4] )){
		hw = eregmatch( pattern: "HW:( )?([0-9]+)", string: sp[4] );
		if(!isnull( hw[2] )){
			set_kb_item( name: "simatic_hmi/snmp/" + port + "/hw_version", value: hw[2] );
		}
	}
}
exit( 0 );

