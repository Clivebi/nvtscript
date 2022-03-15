if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106109" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-06-24 14:37:30 +0700 (Fri, 24 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Meinberg LANTIME Detection (SNMP)" );
	script_tag( name: "summary", value: "Detection of Meinberg NTP Timeserver LANTIME.

  This script performs SNMP based detection of Meinberg NTP Timeserver LANTIME." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_xref( name: "URL", value: "https://www.meinbergglobal.com/english/products/ntp-time-server.htm" );
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
if(ContainsString( sysdesc, "Meinberg LANTIME" )){
	mo = eregmatch( pattern: "LANTIME ([A-Z0-9//]+)", string: sysdesc );
	if(isnull( mo[1] )){
		exit( 0 );
	}
	model = mo[1];
	version = "unknown";
	ver = eregmatch( pattern: "V([0-9.]+)", string: sysdesc );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	set_kb_item( name: "meinberg_lantime/detected", value: TRUE );
	set_kb_item( name: "meinberg_lantime/model", value: model );
	if(version != "unknown"){
		set_kb_item( name: "meinberg_lantime/version", value: version );
	}
	cpe_model = eregmatch( pattern: "[A-Z0-9]+", string: model );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:meinberg:lantime_" + tolower( cpe_model[0] ) + ":" );
	if(isnull( cpe )){
		cpe = "cpe:/a:meinberg:lantime_" + tolower( cpe_model[0] );
	}
	register_product( cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp" );
	log_message( data: build_detection_report( app: "Meinberg LANTIME " + model, version: version, install: port + "/udp", cpe: cpe, concluded: sysdesc ), port: port, proto: "udp" );
}
exit( 0 );

