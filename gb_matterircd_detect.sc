if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108460" );
	script_version( "$Revision: 11395 $" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-14 18:07:01 +0200 (Fri, 14 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-09-14 12:41:10 +0200 (Fri, 14 Sep 2018)" );
	script_name( "matterircd Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ircd.sc" );
	script_require_ports( "Services/irc", 6667, 6697, 7697 );
	script_mandatory_keys( "ircd/banner" );
	script_xref( name: "URL", value: "https://github.com/42wim/matterircd/" );
	script_tag( name: "summary", value: "Detection of a matterircd daemon.

  This script tries to detect a matterircd daemon from a previously gathered IRC banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
port = get_kb_item( "Services/irc" );
if(!port){
	port = 6667;
}
banner = get_kb_item( "irc/banner/" + port );
if(!banner || !ContainsString( banner, "matterircd" )){
	exit( 0 );
}
set_kb_item( name: "matterircd/detected", value: TRUE );
install = port + "/tcp";
version = "unknown";
vers = eregmatch( pattern: "Your host is matterircd, running version ([0-9.]+)", string: banner );
if(vers[1]){
	version = vers[1];
}
cpe = build_cpe( value: version, exp: "^([0-9.]+[0-9])", base: "cpe:/a:42wim:matterircd:" );
if(isnull( cpe )){
	cpe = "cpe:/a:42wim:matterircd";
}
register_product( cpe: cpe, location: install, port: port, service: "irc" );
log_message( data: build_detection_report( app: "matterircd", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

