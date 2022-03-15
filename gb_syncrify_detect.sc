if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100819" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Syncrify Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 5800 );
	script_mandatory_keys( "Apache-Coyote/banner" );
	script_tag( name: "summary", value: "This host is running Syncrify, an incremental, and cloud-ready backup
that implements the rsync protocol over HTTP." );
	script_xref( name: "URL", value: "http://web.synametrics.com/Syncrify.htm" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 5800 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Apache-Coyote" )){
	exit( 0 );
}
url = NASLString( "/app?operation=about" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "Syncrify" ) && "Synametrics Technologies" && ContainsString( buf, "Fast incremental backup" )){
	install = "/";
	vers = NASLString( "unknown" );
	version = eregmatch( string: buf, pattern: "Version: ([0-9.]+) - build ([0-9]+)", icase: TRUE );
	if(!isnull( version[1] )){
		vers = chomp( version[1] );
		if(!isnull( version[2] )){
			vers = vers + "." + version[2];
		}
	}
	set_kb_item( name: NASLString( "www/", port, "/syncrify" ), value: NASLString( vers, " under ", install ) );
	set_kb_item( name: "syncrify/app/detected", value: TRUE );
	info = NASLString( "Syncrify Version '" );
	info += NASLString( vers );
	info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
	info += NASLString( install, "\\n" );
	log_message( port: port, data: info );
	exit( 0 );
}
exit( 0 );

