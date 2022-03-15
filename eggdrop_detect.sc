if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100206" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-06-06T07:39:31+0000" );
	script_tag( name: "last_modification", value: "2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)" );
	script_tag( name: "creation_date", value: "2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Eggdrop Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/eggdrop", 3333 );
	script_tag( name: "summary", value: "This Host is running Eggdrop, an Open Source IRC bot." );
	script_xref( name: "URL", value: "http://www.eggheads.org/" );
	script_timeout( 3600 );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = get_kb_item( "Services/eggdrop" );
if(!port){
	port = 3333;
}
if(!get_port_state( port )){
	exit( 0 );
}
banner = telnet_get_banner( port: port, timeout: 20 );
if(isnull( banner )){
	exit( 0 );
}
if(egrep( pattern: "Eggdrop", string: banner, icase: TRUE )){
	version = eregmatch( string: banner, pattern: "\\(Eggdrop v([0-9.]+[^ ]*) \\(", icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "eggdrop/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9a-z+.]+)", base: "cpe:/a:eggheads:eggdrop:" );
	if(!cpe){
		cpe = "cpe:/a:eggheads:eggdrop";
	}
	register_product( cpe: cpe, location: "/", port: port );
	log_message( data: build_detection_report( app: "Eggdrop", version: vers, install: "/", cpe: cpe, concluded: version[1] ), port: port );
	exit( 0 );
}
exit( 0 );

