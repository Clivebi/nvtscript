if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105421" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-10-27 14:06:30 +0100 (Tue, 27 Oct 2015)" );
	script_name( "Vmware NSX Web Management Interface Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of the Vmware NSX Webinterface" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login.jsp";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>VMware Appliance Management</title>" ) || !ContainsString( buf, "VMW_NSX" )){
	exit( 0 );
}
set_kb_item( name: "vmware_nsx/webui", value: TRUE );
set_kb_item( name: "vmware_nsx/webui/port", value: port );
log_message( data: "Vmware NSX Web Management Interface is running at this port.\n", port: port );
exit( 0 );

