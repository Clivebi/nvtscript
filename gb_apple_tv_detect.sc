if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105899" );
	script_version( "2021-08-09T14:28:51+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 14:28:51 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-09-28 12:11:23 +0200 (Wed, 28 Sep 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apple TV Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 3689 );
	script_mandatory_keys( "iTunes/banner" );
	script_tag( name: "summary", value: "HTTP based detection of Apple TV devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 3689, ignore_broken: TRUE );
banner = http_get_remote_headers( port: 3689, ignore_broken: TRUE );
if(!banner || !IsMatchRegexp( banner, "DAAP-Server\\s*:\\s*iTunes/" ) || !ContainsString( banner, "OS X" )){
	exit( 0 );
}
set_kb_item( name: "apple_tv/detected", value: TRUE );
set_kb_item( name: "apple_tv/http/detected", value: TRUE );
register_product( cpe: "cpe:/a:apple:apple_tv", location: "/", port: port, service: "www" );
register_product( cpe: "cpe:/o:apple:tv", location: "/", port: port, service: "www" );
os_register_and_report( os: "Apple TV", cpe: "cpe:/o:apple:tv", banner_type: "HTTP banner", port: port, desc: "Apple TV Detection", runs_key: "unixoide" );
log_message( port: port, data: "The remote host is an Apple TV device." );
exit( 0 );

