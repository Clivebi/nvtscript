if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105718" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-26T08:48:45+0000" );
	script_tag( name: "last_modification", value: "2020-03-26 08:48:45 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-05-17 12:13:39 +0200 (Tue, 17 May 2016)" );
	script_name( "Symantec Messaging Gateway Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Symantec Messaging Gateway." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_get_installed_sw.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/installed_software/available" );
	exit( 0 );
}
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
if(!infos = snmp_get_sw_oid( pattern: "sms-appliance-release", port: port )){
	exit( 0 );
}
package = infos["package"];
set_kb_item( name: "symantec_smg/detected", value: TRUE );
set_kb_item( name: "symantec_smg/snmp/detected", value: TRUE );
set_kb_item( name: "symantec_smg/snmp/port", value: port );
vers = eregmatch( pattern: "sms-appliance-release-([0-9+][^ $\r\n\"]+)", string: package );
if(!isnull( vers[1] )){
	version = vers[1];
	if(ContainsString( version, "-" )){
		v = split( buffer: version, sep: "-", keep: FALSE );
		version = v[0];
		patch = v[1];
	}
	if(p = snmp_get_sw_oid( pattern: "sms-appliance-patch" )){
		pa = eregmatch( pattern: "sms-appliance-patch-" + version + "-([0-9]+)", string: p[1] );
		if(!isnull( pa[1] )){
			patch = pa[1];
		}
	}
	if(version){
		set_kb_item( name: "symantec_smg/snmp/" + port + "/version", value: version );
	}
	if(patch){
		set_kb_item( name: "symantec_smg/snmp/" + port + "/patch", value: patch );
	}
}
exit( 0 );

