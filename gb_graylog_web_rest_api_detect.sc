if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105758" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-10 13:02:29 +0200 (Fri, 10 Jun 2016)" );
	script_name( "Graylog REST API Detection" );
	script_tag( name: "summary", value: "This script detects the Graylog REST API" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 12900 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 12900 );
url = "/system/cluster/node";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "X-Graylog-Node-ID" ) || !ContainsString( buf, "{\"cluster_id\":" ) || !ContainsString( buf, "is_master" )){
	exit( 0 );
}
cpe = "cpe:/a:torch_gmbh:graylog2";
id = eregmatch( pattern: "X-Graylog-Node-ID: ([^\r\n ]+)", string: buf );
if(!isnull( id[1] )){
	x_graylog_id = id[1];
}
register_product( cpe: cpe, location: "/", port: port, service: "rest_api" );
set_kb_item( name: "graylog/rest/installed", value: TRUE );
report = "The Graylog REST API intercace is running at this port.\nCPE: " + cpe;
if(x_graylog_id){
	report += "\nGraylog Node ID: " + x_graylog_id;
}
log_message( port: port, data: report );
exit( 0 );

