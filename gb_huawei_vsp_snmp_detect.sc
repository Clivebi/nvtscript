if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141199" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-06-19 16:42:10 +0700 (Tue, 19 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei Versatile Security Platform (VSP) Detection (SNMP)" );
	script_tag( name: "summary", value: "SNMP based detection of Huawei Versatile Security Platform (VSP)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_xref( name: "URL", value: "https://e.huawei.com/en/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "Huawei (Storage & Network Security |Symantec )?Versatile Security Platform" )){
	version = "unknown";
	model = "Unknown Model";
	coe_model = "vsp_unknown_model";
	mo = eregmatch( pattern: "Version [0-9.]+ ([^ ]+)", string: sysdesc );
	if(!isnull( mo[1] )){
		model = mo[1];
		cpe_model = tolower( model );
		vers = eregmatch( pattern: model + " (V[0-9A-Z]+)", string: sysdesc );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "huawei_vsp/version", value: version );
		}
	}
	set_kb_item( name: "huawei_vsp/detected", value: TRUE );
	set_kb_item( name: "huawei_vsp/model", value: model );
	set_kb_item( name: "huawei/data_communication_product/detected", value: TRUE );
	cpe = build_cpe( value: tolower( version ), exp: "^(v[0-9a-z]+)", base: "cpe:/h:huawei:" + cpe_model + ":" );
	if(!cpe){
		cpe = "cpe:/h:huawei:" + cpe_model;
	}
	register_product( cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
	log_message( data: build_detection_report( app: "Huawei Versatile Security Platform " + model, version: version, install: port + "/udp", cpe: cpe, concluded: sysdesc ), port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

