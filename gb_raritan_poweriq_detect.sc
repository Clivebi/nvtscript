if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106817" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-05-22 10:12:10 +0700 (Mon, 22 May 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Raritan PowerIQ Detection" );
	script_tag( name: "summary", value: "Detection of Raritan PowerIQ.

The script sends a connection request to the server and attempts to detect Raritan PowerIQ." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.raritan.com/products/dcim-software/power-iq" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
url = "/license/records";
res = http_get_cache( port: port, item: url );
if(egrep( pattern: "^HTTP/.* 302 Found", string: res )){
	data = "sort=id&dir=ASC";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "X-Requested-With", "XMLHttpRequest" ) );
	res = http_keepalive_send_recv( port: port, data: req );
}
if(ContainsString( res, "\"feature\":\"Power IQ\"" )){
	version = "unknown";
	cpe = "cpe:/a:raritan:power_iq";
	set_kb_item( name: "raritan_poweriq/detected", value: TRUE );
	register_product( cpe: cpe, location: "/", port: port );
	log_message( data: build_detection_report( app: "Raritan PowerIQ", version: version, install: "/", cpe: cpe ) );
	exit( 0 );
}
exit( 0 );

