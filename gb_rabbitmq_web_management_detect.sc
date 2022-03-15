if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105178" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-22 17:22:26 +0100 (Thu, 22 Jan 2015)" );
	script_name( "RabbitMQ Web Management Detection" );
	script_tag( name: "summary", value: "The script sends a connection
request to the server and attempts to detect the RabbitMQ webmanagement interface from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 15672 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 15672 );
url = "/";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>RabbitMQ Management</title>" )){
	exit( 0 );
}
cpe = "cpe:/a:pivotal_software:rabbitmq";
register_product( cpe: cpe, location: url, port: port, service: "www" );
set_kb_item( name: "rabbitmq/installed", value: TRUE );
set_kb_item( name: "rabbitmq/web/installed", value: TRUE );
log_message( port: port, data: "RabbitMQ Management Interface is running at this port.\nUrl: " + url + "\nCPE: " + cpe + "\n" );
exit( 0 );

