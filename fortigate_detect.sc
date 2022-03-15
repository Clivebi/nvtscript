if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17367" );
	script_version( "2020-05-05T09:44:01+0000" );
	script_tag( name: "last_modification", value: "2020-05-05 09:44:01 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Fortinet Fortigate console management detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host appears to be a Fortinet Fortigate Firewall." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
port = 443;
if(!get_port_state( port )){
	exit( 0 );
}
req = http_get( item: "/system/console?version=1.5", port: port );
res = http_send_recv( data: req, port: port );
if(ContainsString( res, "<title>" ) && ContainsString( res, "Fortigate Console Access" )){
	log_message( port: port );
}

