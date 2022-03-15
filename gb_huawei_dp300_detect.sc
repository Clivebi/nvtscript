if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141253" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-02 09:32:17 +0200 (Mon, 02 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei DP300 Detection (Telnet)" );
	script_tag( name: "summary", value: "Telnet based detection of Huawei DP300." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 5000 );
	script_mandatory_keys( "telnet/huawei/dp300/detected" );
	script_xref( name: "URL", value: "https://e.huawei.com/en/products/cloud-communications/telepresence-video-conferencing/personal-systems/dp300" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("telnet_func.inc.sc");
port = telnet_get_port( default: 5000 );
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Huawei DP300" )){
	version = "unknown";
	banner = bin2string( ddata: banner, noprint_replacement: " " );
	vers = eregmatch( pattern: "DP300 (V[^ ]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	rel = eregmatch( pattern: "Release ([0-9.]+)", string: banner );
	if(!isnull( rel[1] )){
		set_kb_item( name: "huawei_dp300/release", value: rel[1] );
		extra = "Release:   " + rel[1];
	}
	set_kb_item( name: "huawei_dp300/detected", value: TRUE );
	set_kb_item( name: "huawei/data_communication_product/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^(V[0-9A-Z]+)", base: "cpe:/h:huawei:dp300:" );
	if(!cpe){
		cpe = "cpe:/h:huawei:dp300";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "telnet" );
	log_message( data: build_detection_report( app: "Huawei DP300", version: version, install: port + "/tcp", cpe: cpe, concluded: vers[0], extra: extra ), port: port );
}
exit( 0 );

