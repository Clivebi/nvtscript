if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108489" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-11-28 14:02:54 +0100 (Wed, 28 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Western Digital My Cloud Products Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "SNMP based detection of Western Digital My Cloud products." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc || !IsMatchRegexp( sysdesc, "^Linux" )){
	exit( 0 );
}
version = "unknown";
sw_oid = "1.3.6.1.4.1.5127.1.1.1.8.1.2.0";
sw_res = snmp_get( port: port, oid: sw_oid );
if(!sw_res){
	exit( 0 );
}
vers = eregmatch( pattern: "^([0-9.]+)", string: sw_res );
if(vers[1]){
	version = vers[1];
	model = "unknown";
	mod_oid = "1.3.6.1.4.1.5127.1.1.1.8.1.3.0";
	mod_res = snmp_get( port: port, oid: mod_oid );
	if(mod_res && mod_res == "MyCloudEX2Ultra"){
		model = "EX2Ultra";
		set_kb_item( name: "wd-mycloud/snmp/" + port + "/concludedMod", value: mod_res );
		set_kb_item( name: "wd-mycloud/snmp/" + port + "/concludedModOID", value: mod_oid );
	}
	set_kb_item( name: "wd-mycloud/detected", value: TRUE );
	set_kb_item( name: "wd-mycloud/snmp/detected", value: TRUE );
	set_kb_item( name: "wd-mycloud/snmp/port", value: port );
	set_kb_item( name: "wd-mycloud/snmp/" + port + "/concludedVers", value: sw_res );
	set_kb_item( name: "wd-mycloud/snmp/" + port + "/concludedVersOID", value: sw_oid );
	set_kb_item( name: "wd-mycloud/snmp/" + port + "/version", value: version );
	set_kb_item( name: "wd-mycloud/snmp/" + port + "/model", value: model );
}
exit( 0 );

