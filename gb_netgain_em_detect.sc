if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106631" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-07 08:12:26 +0700 (Tue, 07 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NetGain Enterprise Manager Detection" );
	script_tag( name: "summary", value: "Detection of NetGain Enterprise Manager

The script sends a HTTP connection request to the server and attempts to detect the presence of NetGain Enterprise
Manager and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.netgain-systems.com/netgain-enterprise-manager/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( res, "<title>NetGain (Enterprise Manager|EM)" ) && IsMatchRegexp( res, "NetGain Systems.*All rights reserved" )){
	version = "unknown";
	vers = eregmatch( pattern: "<div class=\"version\">v([0-9.]+)( build ([0-9]+))?", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		if(!isnull( vers[3] )){
			version += "." + vers[3];
		}
		set_kb_item( name: "netgain_em/version", value: version );
	}
	set_kb_item( name: "netgain_em/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:netgain:enterprise_manager:" );
	if(!cpe){
		cpe = "cpe:/a:netgain:enterprise_manager";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "NetGain Enterprise Manager", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );
