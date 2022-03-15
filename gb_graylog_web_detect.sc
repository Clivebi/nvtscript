if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105755" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-10 13:02:29 +0200 (Fri, 10 Jun 2016)" );
	script_name( "Graylog Webinterface Detection" );
	script_tag( name: "summary", value: "This script detects the Graylog Webinterface" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( port: port, item: "/" );
if(!ContainsString( buf, "<title>Graylog Web Interface</title>" ) || !ContainsString( buf, "X-Graylog-Node-ID" )){
	exit( 0 );
}
cpe = "cpe:/a:torch_gmbh:graylog2";
id = eregmatch( pattern: "X-Graylog-Node-ID: ([^\r\n ]+)", string: buf );
if(!isnull( id[1] )){
	x_graylog_id = id[1];
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
set_kb_item( name: "graylog/installed", value: TRUE );
report = "The Graylog Webinterface is running at this port.\nCPE: " + cpe;
if(x_graylog_id){
	report += "\nGraylog Node ID: " + x_graylog_id;
}
log_message( port: port, data: report );
exit( 0 );

