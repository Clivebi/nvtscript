if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140762" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-12 11:15:29 +0700 (Mon, 12 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Small Business RV13x Series Router Detection" );
	script_tag( name: "summary", value: "Detection of Cisco Small Business RV13x Series Router.

The script sends a connection request to the server and attempts to detect Cisco Small Business RV13x Series
Router." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/products/routers/small-business-rv-series-routers/index.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/login.htm" );
if(ContainsString( res, "router.appname=\"RV13" ) && ContainsString( res, "router.ciscosb" )){
	version = "unknown";
	mod = eregmatch( pattern: "router.appname=\"(RV13[^ ]+)", string: res );
	if(isnull( mod[1] )){
		exit( 0 );
	}
	model = mod[1];
	cpe = "cpe:/a:cisco:" + tolower( model );
	set_kb_item( name: "cisco_rv13x/detected", value: TRUE );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Cisco Small Business " + model, version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

