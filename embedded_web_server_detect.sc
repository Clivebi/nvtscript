if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19689" );
	script_version( "2021-03-18T13:55:00+0000" );
	script_tag( name: "last_modification", value: "2021-03-18 13:55:00 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Embedded Web Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 TNS" );
	script_family( "Service detection" );
	script_dependencies( "cisco_ids_manager_detect.sc", "clearswift_mimesweeper_smtp_detect.sc", "cobalt_web_admin_server.sc", "DDI_Cabletron_Web_View.sc", "imss_detect.sc", "interspect_detect.sc", "intrushield_console_detect.sc", "iwss_detect.sc", "raptor_detect.sc", "securenet_provider_detect.sc", "sitescope_management_server.sc", "sun_cobalt_adaptive_firewall_detect.sc", "tmcm_detect.sc", "websense_detect.sc", "xedus_detect.sc", "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This plugin determines if the remote web server is an embedded service
  (without any user-supplied CGIs)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_get_is_marked_embedded( port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "^[Ss]erver\\s*:\\s*(CUPS|MiniServ|AppleShareIP|Embedded Web Server|Embedded HTTPD|IP_SHARER|Ipswitch-IMail|MACOS_Personal_Websharing|NetCache appliance|ZyXEL-RomPager|cisco-IOS|u-Server|eMule|Allegro-Software-RomPager|RomPager|Desktop On-Call|D-Link|4D_WebStar|IPC@CHIP|Citrix Web PN Server|SonicWALL|Micro-Web|gSOAP|CompaqHTTPServer/|BBC [0-9.]+; .*[cC]oda)", string: banner ) || port == 901 || egrep( pattern: "^Webserver:$", string: banner )){
	http_set_is_marked_embedded( port: port );
}
exit( 0 );

