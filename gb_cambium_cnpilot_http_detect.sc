if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140630" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cambium Networks cnPilot Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Cambium Networks cnPilot over HTTP

The script sends a connection request to the server and attempts to detect Cambium Networks cnPilot and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.cambiumnetworks.com/products/wifi/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/index.asp" );
if(ContainsString( res, "product_name=\"cnPilot" )){
	set_kb_item( name: "cambium_cnpilot/detected", value: TRUE );
	set_kb_item( name: "cambium_cnpilot/http/detected", value: TRUE );
	set_kb_item( name: "cambium_cnpilot/http/port", value: port );
	mod = eregmatch( pattern: "product_name=\"cnPilot ([^\"]+)", string: res );
	if(!isnull( mod[1] )){
		set_kb_item( name: "cambium_cnpilot/http/" + port + "/model", value: mod[1] );
	}
	vers = eregmatch( pattern: "Capture.status_basic.firmware_v.</script></td>.*([0-9].[0-9].[0-9]-R[0-9])", string: res );
	if(isnull( vers[1] )){
		vers = eregmatch( pattern: "Capture.status_basic.firmware_v.</script></td>.*([0-9].[0-9]-R[0-9])", string: res );
	}
	if(!isnull( vers[1] )){
		set_kb_item( name: "cambium_cnpilot/http/" + port + "/fw_version", value: vers[1] );
		set_kb_item( name: "cambium_cnpilot/http/" + port + "/concluded", value: vers[0] );
	}
}
exit( 0 );

