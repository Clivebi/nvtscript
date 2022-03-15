if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141417" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-31 11:26:59 +0700 (Fri, 31 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Xovis PC-Series Sensor Detection" );
	script_tag( name: "summary", value: "Detection of Xovis PC-Series Sensors.

The script sends a connection request to the server and attempts to detect Xovis PC-Series Sensors and to extract
it's version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://xovis.com/en/products/retail-products/#section-66" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>Xovis Sensor</title>" ) && ContainsString( res, "sensorui/sensorui.nocache.js" )){
	version = "unknown";
	url = "/api/info/sensor-status";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	mod = eregmatch( pattern: "<device-type .*>([^<]+)</device-type>", string: res );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	vers = eregmatch( pattern: "version type=\"SW\">([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	name = eregmatch( pattern: "<name>([^<]+)", string: res );
	if(!isnull( name[1] )){
		extra += "Name:          " + name[1];
	}
	group = eregmatch( pattern: "<group>([^<]+)", string: res );
	if(!isnull( group[1] )){
		extra += "\nGroup:         " + group[1];
	}
	mac = eregmatch( pattern: "<serial-number>([A-F0-9:]{17})<", string: res );
	if(!isnull( mac[1] )){
		register_host_detail( name: "MAC", value: mac[1], desc: "gb_siemens_xovis_pc_sensor_detect.nasl" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
		extra += "\nMAC Address:   " + mac[1];
	}
	set_kb_item( name: "xovis_pc_sensor/detected", value: TRUE );
	if( model ) {
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:xovis:" + tolower( model ) + ":" );
	}
	else {
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:xovis:pc_sensor:" );
	}
	if(!cpe){
		if( model ) {
			cpe = "cpe:/a:xovis:" + tolower( model );
		}
		else {
			cpe = "cpe:/a:xovis:pc_sensor";
		}
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Xovis " + model + " Sensor", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

