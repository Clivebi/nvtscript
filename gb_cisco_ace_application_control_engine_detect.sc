if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106257" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-09-16 15:00:47 +0700 (Fri, 16 Sep 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco ACE Application Control Engine Detection" );
	script_tag( name: "summary", value: "Detection of Cisco ACE Application Control Engine

The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "cuesLoginProductName\">ACE 4710 Device Manager" )){
	version = "unknown";
	cpe = "cpe:/h:cisco:ace_4710";
	vers = eregmatch( pattern: "cuesLoginVersionInfo\">Version ([^<]+)</div>", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "cisco_ace/version", value: version );
		cpe = cpe + ":" + tolower( version );
	}
	set_kb_item( name: "cisco_ace/detected", value: TRUE );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Cisco ACE 4710 Application Control Engine", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

