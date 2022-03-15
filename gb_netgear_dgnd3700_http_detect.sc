if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112334" );
	script_version( "2021-08-12T14:07:30+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 14:07:30 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2018-07-25 09:22:12 +0200 (Wed, 25 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NETGEAR DGND3700 Router Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of NETGEAR DGND3700 Routers." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "DGND3700/banner" );
	script_xref( name: "URL", value: "https://www.netgear.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(concl = egrep( string: banner, pattern: "^WWW-Authenticate\\s*:\\s*Basic realm=\"NETGEAR DGND3700", icase: TRUE )){
	concl = chomp( concl );
	set_kb_item( name: "netgear/dgnd3700/detected", value: TRUE );
	set_kb_item( name: "netgear/dgnd3700/http/detected", value: TRUE );
	set_kb_item( name: "netgear/router/detected", value: TRUE );
	set_kb_item( name: "netgear/router/http/detected", value: TRUE );
	version = "unknown";
	install = "/";
	os_cpe = "cpe:/o:netgear:dgnd3700_firmware";
	hw_cpe = "cpe:/h:netgear:dgnd3700";
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	os_register_and_report( os: "NETGEAR DGND3700 Firmware", cpe: os_cpe, runs_key: "unixoide", desc: "NETGEAR DGND3700 Router Detection (HTTP)" );
	report = build_detection_report( app: "NETGEAR DGND3700 Firmware", version: version, install: install, cpe: os_cpe );
	report += "\n\n" + build_detection_report( app: "NETGEAR DGND3700", install: install, cpe: hw_cpe, skip_version: TRUE );
	report += "\n\nConcluded from version/product identification result:\n\n" + concl;
	log_message( port: port, data: report );
}
exit( 0 );

