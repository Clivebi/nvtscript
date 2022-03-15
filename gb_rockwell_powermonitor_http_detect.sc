if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142010" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-02-20 16:34:48 +0700 (Wed, 20 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Rockwell Automation PowerMonitor Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Rockwell Automation PowerMonitor
devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://ab.rockwellautomation.com/Energy-Monitoring/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/overview.shtm" );
if(ContainsString( res, "Rockwell Automation" ) && ContainsString( res, "<title>PowerMonitor" )){
	version = "unknown";
	res2 = http_get_cache( port: port, item: "/" );
	mod = eregmatch( pattern: "<title>Powermonitor ([0-9]+)", string: res2, icase: TRUE );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	vers = eregmatch( pattern: "\"Firmware_Revision\">Revision ([0-9.]+)", string: res );
	if( !isnull( vers[1] ) ) {
		version = vers[1];
	}
	else {
		vers = eregmatch( pattern: "\"OS\">([0-9]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	mac = eregmatch( pattern: "\"Ethernet_Address\">([A-F0-9:]{17})", string: res );
	if(!isnull( mac[1] )){
		register_host_detail( name: "MAC", value: mac[1], desc: "gb_rockwell_powermonitor_http_detect.nasl" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
		extra = "Mac Address:   " + mac[1] + "\n";
	}
	set_kb_item( name: "rockwell_powermonitor/detected", value: TRUE );
	if( model ){
		app_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:rockwellautomation:powermonitor" + model + ":" );
		os_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:rockwellautomation:powermonitor" + model + ":" );
		hw_cpe = "cpe:/h:rockwellautomation:powermeter" + model;
	}
	else {
		app_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:rockwellautomation:powermonitor:" );
		os_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:rockwellautomation:powermonitor:" );
		hw_cpe = "cpe:/h:rockwellautomation:powermeter";
	}
	os_register_and_report( os: "Rockwell Automation PowerMonitor Firmware", cpe: os_cpe, desc: "Rockwell Automation PowerMonitor Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
	register_product( cpe: os_cpe, location: "/", port: port, service: "www" );
	register_product( cpe: app_cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Rockwell Automation PowerMonitor " + model, version: version, install: "/", cpe: app_cpe, concluded: vers[0], extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

