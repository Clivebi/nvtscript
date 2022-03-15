if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106695" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-27 14:18:27 +0700 (Mon, 27 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Nuxeo Platform Detection" );
	script_tag( name: "summary", value: "Detection of Nuxeo Platform.

  The script sends a HTTP connection request to the server and attempts to detect the presence of Nuxeo Platform and
  to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.nuxeo.com/products/content-management-platform/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_ka_recv_buf( port: port, url: "/nuxeo/login.jsp" );
if(ContainsString( res, "nxtimezone.js" ) && ContainsString( res, "nxstartup.faces" ) && ContainsString( res, "Nuxeo and respective authors" )){
	version = "unknown";
	install = "/nuxeo";
	vers = eregmatch( pattern: "&nbsp;.{10}([^\r\n]+)", string: res );
	if(!isnull( vers[1] )){
		version = chomp( vers[1] );
		set_kb_item( name: "nuxeo_platform/version", value: version );
	}
	set_kb_item( name: "nuxeo_platform/installed", value: TRUE );
	cpe_vers = str_replace( string: tolower( version ), find: " ", replace: "-" );
	cpe = build_cpe( value: cpe_vers, exp: "([0-9lts.-]+)", base: "cpe:/a:nuxeo:platform:" );
	if(!cpe){
		cpe = "cpe:/a:nuxeo:platform";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Nuxeo Platform", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

