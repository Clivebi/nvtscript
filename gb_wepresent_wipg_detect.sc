if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106781" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-21 08:12:54 +0200 (Fri, 21 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "wePresent WiPG Device Detection" );
	script_tag( name: "summary", value: "Detection of wePresent WiPG devices.

The script sends a connection request to the server and attempts to detect wePresent WiPG devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.wepresentwifi.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
req = http_get( port: port, item: "/cgi-bin/web_index.cgi?lang=en&src=AwWelcome.html" );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "<title>wePresent" ) && ( ( ContainsString( res, "AwLoginTrainer.html" ) && ContainsString( res, "AwLoginAdmin.html" ) ) || ContainsString( res, "AwLoginBS.html" ) )){
	version = "unknown";
	model = "";
	cpe = "cpe:/a:wepresent:wipg";
	mod = eregmatch( pattern: "wePresent WiPG-([0-9]+)([A-Z])?", string: res );
	if(!isnull( mod[1] )){
		model = mod[1];
		set_kb_item( name: "wepresent_wipg/model", value: model );
		cpe += "-" + model;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "wePresent WiPG " + model, version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

