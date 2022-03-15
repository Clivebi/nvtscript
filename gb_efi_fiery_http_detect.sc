if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140654" );
	script_version( "2021-09-10T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 14:44:58 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 13:06:22 +0700 (Fri, 05 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "EFI Fiery Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of EFI Fiery." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/wt4/home";
res = http_get_cache( port: port, item: url );
if(!ContainsString( res, "<title>WebTools" ) || !ContainsString( res, "id-footer-efi-logo" )){
	url = "/wt2parser.cgi?home_en";
	res = http_get_cache( port: port, item: url );
	if(!ContainsString( res, "<title>Webtools" ) || !ContainsString( res, "<span class=\"footertext\">&copy; EFI" ) || !ContainsString( res, "wt2parser.cgi?status_en.htm" )){
		exit( 0 );
	}
}
version = "unknown";
vers = eregmatch( pattern: "<td class=\"printer-name\">([^<]+)", string: res );
if( !isnull( vers[1] ) ){
	version = vers[1];
	set_kb_item( name: "efi/fiery/http/" + port + "/concluded", value: vers[0] );
}
else {
	vers = eregmatch( pattern: "\"version-name\">([^<]+)<", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "efi/fiery/http/" + port + "/concluded", value: vers[0] );
	}
}
concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
set_kb_item( name: "efi/fiery/detected", value: TRUE );
set_kb_item( name: "efi/fiery/http/detected", value: TRUE );
set_kb_item( name: "efi/fiery/http/port", value: port );
set_kb_item( name: "efi/fiery/http/" + port + "/version", value: version );
set_kb_item( name: "efi/fiery/http/" + port + "/concludedUrl", value: concUrl );
exit( 0 );

