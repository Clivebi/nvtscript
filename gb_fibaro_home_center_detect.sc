if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140419" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-09-29 12:10:53 +0700 (Fri, 29 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "FIBARO Home Center Detection" );
	script_tag( name: "summary", value: "Detection of FIBARO Home Center.

The script sends a connection request to the server and attempts to detect FIBARO Home Center and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.fibaro.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8081 );
req = http_get( port: port, item: "/fibaro/en/home/login.html" );
res = http_keepalive_send_recv( port: port, data: req );
if("<title>(Fibaro )?Home Center" && ( ContainsString( res, "com.fibaro.plugins" ) || ContainsString( res, "zwaveDeviceConfigurationIcons" ) )){
	version = "unknown";
	url = "/api/settings/info";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	mod = eregmatch( pattern: "serialNumber\":\"([^-]+)", string: res );
	if(!isnull( mod[1] )){
		if( mod[1] == "HCL" ){
			model = "Lite";
			set_kb_item( name: "fibaro_home_center/model", value: model );
		}
		else {
			if(mod[1] == "HC2"){
				model = "2";
				set_kb_item( name: "fibaro_home_center/model", value: model );
			}
		}
	}
	vers = eregmatch( pattern: "\"softVersion\":\"([0-9.]+)\"", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "fibaro_home_center/version", value: version );
		concUrl = url;
	}
	hcname = eregmatch( pattern: "\"hcName\":\"([^\"]+)", string: res );
	if(!isnull( hcname[1] )){
		info += "Name:            " + hcname[1] + "\\n";
	}
	mac = eregmatch( pattern: "mac\":\"([0-9a-f:]{17})\"", string: res );
	if(!isnull( mac[1] )){
		info += "MAC:             " + mac[1] + "\\n";
		register_host_detail( name: "MAC", value: mac[1], desc: "gb_fibaro_home_center_detect.nasl" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
	}
	zwave_vers = eregmatch( pattern: "\"zwaveVersion\":\"([0-9.]+)\"", string: res );
	if(!isnull( zwave_vers[1] )){
		info += "Z-Wave version:  " + zwave_vers[1] + "\\n";
		set_kb_item( name: "fibaro_home_center/zwave_version", value: zwave_vers );
	}
	set_kb_item( name: "fibaro_home_center/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:fibaro:home_center:" );
	if(!cpe){
		cpe = "cpe:/a:fibaro:home_center";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "FIBARO Home Center " + model, version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: info ), port: port );
	exit( 0 );
}
exit( 0 );

