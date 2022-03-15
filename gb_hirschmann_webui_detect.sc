if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140575" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-04 14:40:12 +0700 (Mon, 04 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Hirschmann Devices Detection (Web UI)" );
	script_tag( name: "summary", value: "Detection of Hirschmann devices over HTTP.

The script sends a connection request to the server and attempts to detect Hirschmann devices and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.hirschmann.com/en/Hirschmann_Produkte/index.phtml" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
known_platforms = make_list( "L2B",
	 "L2E",
	 "L2P",
	 "L3E",
	 "L3P",
	 "HiOS-3S" );
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "VALUE=\"com.hirschmann." ) && ContainsString( res, "productName" ) ) || ( ContainsString( res, "img/hirschLogo.gif" ) && ContainsString( res, "GAI.SESSIONID" ) )){
	set_kb_item( name: "hirschmann_device/detected", value: TRUE );
	set_kb_item( name: "hirschmann_device/http/detected", value: TRUE );
	set_kb_item( name: "hirschmann_device/http/port", value: port );
	fw_version = "unknown";
	product_name = "unknown";
	platform_name = "unknown";
	prod_name = eregmatch( pattern: "\"productName\" VALUE=\"([^\"]+)", string: res );
	if( isnull( prod_name[1] ) ){
		prod_name = eregmatch( pattern: "<title>([^<]+)", string: res );
		if(!isnull( prod_name[1] )){
			product_name = prod_name[1];
		}
		concluded += prod_name[0] + "\n";
	}
	else {
		product_name = prod_name[1];
		concluded += prod_name[0] + "\n";
	}
	vers = eregmatch( pattern: "\"productVersion\" VALUE=\"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		fw_version = vers[1];
		concluded += vers[0] + "\n";
	}
	pltf_name = egrep( pattern: "\"launchClass\" VALUE=\"com\\.hirschmann\\.products\\.apps\\.", string: res );
	if(!isnull( pltf_name )){
		for known_platform in known_platforms {
			if(ContainsString( pltf_name, known_platform )){
				platform_name = known_platform;
				break;
			}
		}
		concluded += pltf_name + "\n";
	}
	set_kb_item( name: "hirschmann_device/http/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "hirschmann_device/http/" + port + "/product_name", value: product_name );
	set_kb_item( name: "hirschmann_device/http/" + port + "/platform_name", value: platform_name );
	if(concluded){
		set_kb_item( name: "hirschmann_device/http/" + port + "/concluded", value: concluded );
	}
}
exit( 0 );

