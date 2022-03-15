if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14644" );
	script_version( "2021-03-19T13:48:08+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 13:48:08 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Xedus Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 4274 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Xedus." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
exit( 0 );
port = http_get_port( default: 4274 );
url = "/testgetrequest.x?param='free%20nvttest'";
req = http_get( item: url, port: port );
rep = http_keepalive_send_recv( port: port, data: req );
if(egrep( pattern: "free nvttest", string: rep )){
	set_kb_item( name: "xedus/running", value: TRUE );
	set_kb_item( name: "xedus/" + port + "/running", value: TRUE );
	http_set_is_marked_embedded( port: port );
	log_message( port: port );
}
exit( 0 );

