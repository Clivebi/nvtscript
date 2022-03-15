if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105176" );
	script_version( "2021-06-14T08:39:07+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 08:39:07 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-01-21 12:16:43 +0100 (Wed, 21 Jan 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Global Console Manager (GCM) Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of IBM Global Console Manager (GCM)." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login.php";
buf = http_get_cache( port: port, item: url );
if(egrep( pattern: "<title>GCM(16|32) Explorer</title>", string: buf ) && ContainsString( buf, ">User Login" )){
	version = "unknown";
	set_kb_item( name: "ibm/gcm/detected", value: TRUE );
	set_kb_item( name: "ibm/gcm/http/detected", value: TRUE );
	if( ContainsString( buf, "GCM16" ) ) {
		cpe = "cpe:/o:ibm:global_console_manager_16_firmware";
	}
	else {
		cpe = "cpe:/o:ibm:global_console_manager_32_firmware";
	}
	os_register_and_report( os: "IBM Global Console Manager Firmware", cpe: cpe, runs_key: "unixoide", desc: "IBM Global Console Manager (GCM) Detection (HTTP)" );
	register_product( cpe: cpe, location: url, port: port, service: "www" );
	log_message( data: build_detection_report( app: "IBM Global Console Manager", version: version, cpe: cpe, install: "/" ), port: port );
	exit( 0 );
}
exit( 0 );

