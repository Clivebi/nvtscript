if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20377" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Windows Server Update Services detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 David Maciejak" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8530 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.microsoft.com/windowsserversystem/updateservices/default.mspx" );
	script_tag( name: "summary", value: "The remote host appears to be running Windows Server Update
  Services.

  Description:

  This product is used to deploy easily and quickly latest
  Microsoft product updates." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8530 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
req = http_get( item: "/Wsusadmin/Errors/BrowserSettings.aspx", port: port );
r = http_keepalive_send_recv( port: port, data: req );
if(!r){
	exit( 0 );
}
if(egrep( pattern: "<title>Windows Server Update Services error</title>.*href=\"/WsusAdmin/Common/Common.css\"", string: r ) || egrep( pattern: "<div class=\"CurrentNavigation\">Windows Server Update Services error</div>", string: r )){
	log_message( port: port );
}
exit( 0 );

