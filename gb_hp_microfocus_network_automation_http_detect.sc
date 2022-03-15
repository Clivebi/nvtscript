if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106329" );
	script_version( "2021-09-09T08:54:27+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:54:27 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 11:00:37 +0700 (Thu, 01 Dec 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Micro Focus / HP Network Automation Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Micro Focus / HP Network Automation." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.microfocus.com/en-us/products/network-automation/overview" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( res, "<title>(HPE? )?Network Automation" ) && ( IsMatchRegexp( res, "HPE? Network Automation Log In Help" ) || IsMatchRegexp( res, "\"login_appname\">HPE? Network Automation<" ) || ContainsString( res, "class=\"form-title expanding-animation\">Network Automation<" ) )){
	version = "unknown";
	vers = eregmatch( pattern: "(HPE? )?Network Automation ([0-9.]+): Login", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
	set_kb_item( name: "microfocus/network_automation/detected", value: TRUE );
	set_kb_item( name: "microfocus/network_automation/http/detected", value: TRUE );
	cpe1 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:microfocus:network_automation:" );
	cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:network_automation:" );
	if(!cpe1){
		cpe1 = "cpe:/a:microfocus:network_automation";
		cpe2 = "cpe:/a:hp:network_automation";
	}
	register_product( cpe: cpe1, location: "/", port: port, service: "www" );
	register_product( cpe: cpe2, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Micro Focus / HP Network Automation", version: version, install: "/", cpe: cpe1, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

