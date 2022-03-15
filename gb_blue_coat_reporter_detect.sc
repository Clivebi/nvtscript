if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103245" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-08 15:23:37 +0200 (Thu, 08 Sep 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Blue Coat Reporter Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "BCReport/banner" );
	script_xref( name: "URL", value: "http://www.bluecoat.com/products/proxysg/addons/reporter" );
	script_tag( name: "summary", value: "This host is running the Blue Coat Reporter." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || ( !ContainsString( banner, "BCReport" ) && !ContainsString( banner, "Blue Coat Reporter" ) )){
	exit( 0 );
}
buf = http_get_cache( item: "/", port: port );
if(!buf){
	exit( 0 );
}
if(egrep( pattern: "Blue Coat Reporter", string: buf, icase: TRUE )){
	set_kb_item( name: "bluecoat/reporter/detected", value: TRUE );
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "[ \t\r\n]alert[ \t]*\\([ \t]*\"Blue Coat Reporter:[ \t]*([0-9.]+).*-[ \t]*build number:[ \t]*([0-9]+))\"" );
	if( !isnull( version ) ){
		vers = version[1];
		if(!isnull( version[2] )){
			set_kb_item( name: "bluecoat/reporter/build", value: version[2] );
			extra = "Build " + version[2];
		}
	}
	else {
		server_info = eregmatch( pattern: "src=\"(serverinfo.js\\?cb=[^\"]+)\"", string: buf );
		if(!isnull( server_info[1] )){
			url = "/" + server_info[1];
			req = http_get( item: url, port: port );
			buf1 = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			version = eregmatch( string: buf1, pattern: "version='([0-9.]+)'.*build='([0-9]+)'", icase: TRUE );
			if(!isnull( version )){
				vers = version[1];
				if(!isnull( version[2] )){
					set_kb_item( name: "bluecoat/reporter/build", value: version[2] );
					extra = "Build " + version[2];
				}
			}
		}
	}
	register_and_report_cpe( app: "Blue Coat Reporter", ver: vers, concluded: version[0], base: "cpe:/a:bluecoat:reporter:", expr: "^([0-9.]+)", insloc: "/", regService: "www", regPort: port, conclUrl: url, extra: extra );
}
exit( 0 );

