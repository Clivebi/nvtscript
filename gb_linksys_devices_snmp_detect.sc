if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144534" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-09-08 06:13:55 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Linksys Device Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of Linksys devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(egrep( pattern: "Linksys", string: sysdesc, icase: TRUE )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "linksys/detected", value: TRUE );
	set_kb_item( name: "linksys/snmp/port", value: port );
	set_kb_item( name: "linksys/snmp/" + port + "/concluded", value: sysdesc );
	mod = eregmatch( pattern: "Linksys ([A-Z]+[^ ]+)", string: sysdesc, icase: TRUE );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	set_kb_item( name: "linksys/snmp/" + port + "/model", value: model );
	set_kb_item( name: "linksys/snmp/" + port + "/version", value: version );
}
exit( 0 );

