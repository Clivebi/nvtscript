if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105787" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-30 13:36:05 +0200 (Thu, 30 Jun 2016)" );
	script_name( "Riverbed SteelCentral Detection (HTTP)" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
source = "http";
port = http_get_port( default: 443 );
buf = http_get_cache( port: port, item: "/" );
if(ContainsString( buf, "<title>Riverbed Technology, Inc.</title>" )){
	url = "/api/common/1.0/info";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "device_name" ) && ContainsString( buf, "sw_version" ) && ContainsString( buf, "model" )){
		set_kb_item( name: "riverbed/SteelCentral/detected", value: TRUE );
		if(ContainsString( buf, "-VE" )){
			set_kb_item( name: "riverbed/SteelCentral/is_vm", value: TRUE );
		}
		set_kb_item( name: "riverbed/SteelCentral/http_interface/detected", value: TRUE );
		cpe = "cpe:/a:riverbed:steelcentral";
		vers = "unknown";
		report_app = "Riverbed SteelCentral";
		report_version = "";
		version = eregmatch( pattern: "sw_version=\"([0-9.]+[^ (\"\r\n]+)", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
			report_version = vers;
			cpe += ":" + vers;
			set_kb_item( name: "riverbed/SteelCentral/" + source + "/version", value: vers );
		}
		rls = eregmatch( pattern: "sw_version=\"[0-9.]+ \\(release ([^) ]+)\\)", string: buf );
		if(!isnull( rls[1] )){
			release = rls[1];
			report_version += " (" + release + ")";
			set_kb_item( name: "riverbed/SteelCentral/" + source + "/release", value: release );
		}
		mod = eregmatch( pattern: "model=\"([^\"]+)\"", string: buf );
		if(!isnull( mod[1] )){
			model = mod[1];
			report_app += " (" + model + ")";
			set_kb_item( name: "riverbed/SteelCentral/" + source + "/model", value: model );
		}
		register_product( cpe: cpe, location: "/", port: port, service: "www" );
		report = build_detection_report( app: report_app, version: report_version, install: "/", cpe: cpe, concluded: "/api/common/1.0/info" );
		log_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

