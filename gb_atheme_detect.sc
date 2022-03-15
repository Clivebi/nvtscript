if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106633" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-07 08:12:26 +0700 (Tue, 07 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Atheme IRC NickServ Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Atheme IRC NickServ.

  The script sends a HTTP connection request to the server and attempts to detect the presence of the Atheme IRC
  NickServ and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Atheme/banner" );
	script_xref( name: "URL", value: "http://atheme.net/atheme.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(concl = egrep( string: banner, pattern: "^Server: Atheme", icase: TRUE )){
	version = "unknown";
	concl = chomp( concl );
	vers = eregmatch( pattern: "Server: Atheme/([0-9a-zA-Z.-]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "atheme/version", value: version );
		concl = vers[0];
	}
	set_kb_item( name: "atheme/installed", value: TRUE );
	cpe = build_cpe( value: tolower( version ), exp: "^([0-9a-z.-]+)", base: "cpe:/a:atheme:atheme:" );
	if(!cpe){
		cpe = "cpe:/a:atheme:atheme";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Atheme IRC NickServ", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
	exit( 0 );
}
exit( 0 );

