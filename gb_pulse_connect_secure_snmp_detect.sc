if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811737" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-09-11 19:06:34 +0530 (Mon, 11 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Pulse Connect Secure Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of Pulse Connect Secure." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
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
if(ContainsString( sysdesc, "Pulse Connect Secure" ) && ContainsString( sysdesc, "Pulse Secure" )){
	model = "unknown";
	version = "unknown";
	set_kb_item( name: "pulsesecure/detected", value: TRUE );
	set_kb_item( name: "pulsesecure/snmp/port", value: port );
	set_kb_item( name: "pulsesecure/snmp/" + port + "/concluded", value: sysdesc );
	details = eregmatch( pattern: "Connect Secure,([^,]+),([0-9R.]+)", string: sysdesc );
	if(!isnull( details[1] )){
		model = details[1];
		version = details[2];
	}
	set_kb_item( name: "pulsesecure/snmp/" + port + "/version", value: version );
	set_kb_item( name: "pulsesecure/snmp/" + port + "/model", value: model );
}
exit( 0 );

