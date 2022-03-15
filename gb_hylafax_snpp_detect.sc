if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141497" );
	script_version( "$Revision: 11514 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-21 10:27:11 +0200 (Fri, 21 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-09-21 13:11:31 +0700 (Fri, 21 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HylaFAX Detection (SNPP)" );
	script_tag( name: "summary", value: "Detection of HylaFAX over SNPP.

The script sends a connection request to the server and attempts to detect HylaFAX and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service_3digits.sc" );
	script_require_ports( "Services/hylafax", 444 );
	script_xref( name: "URL", value: "https://www.ifax.com/products/fax-software/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = get_kb_item( "Services/hylafax" );
if(!port){
	port = 444;
}
if(!get_port_state( port )){
	exit( 0 );
}
banner = get_kb_item( "FindService/tcp/" + port + "/help" );
if(ContainsString( banner, "SNPP server (HylaFAX" )){
	version = "unknown";
	vers = eregmatch( pattern: "Version ([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "hylafax/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:hylafax:hylafax:" );
	if(!cpe){
		cpe = "cpe:/a:hylafax:hylafax";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "snpp" );
	log_message( data: build_detection_report( app: "HylaFAX", version: version, install: port + "/tcp", cpe: cpe, concluded: banner ), port: port );
	exit( 0 );
}
exit( 0 );

