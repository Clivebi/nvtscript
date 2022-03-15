if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103147" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "up.time Detection" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9999 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running up.time, a server monitoring software." );
	script_xref( name: "URL", value: "http://www.uptimesoftware.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/index.php";
buf = http_get_cache( item: url, port: port );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "<title>up.time" ) && ( ContainsString( buf, "Please Enter Your Username and Password to Log In:" ) || ContainsString( buf, "/styles/uptime.css" ) )){
	install = "/";
	vers = "unknown";
	version = eregmatch( pattern: "<li>up.time ([^ ]+) \\(build ([^)]+)\\)</li>", string: buf );
	if(isnull( version[1] )){
		version = eregmatch( pattern: "/styles/uptime.css\\?v=([0-9.]+).([0-9]+)", string: buf );
	}
	if(!isnull( version[1] )){
		vers = version[1];
	}
	if(!isnull( version[2] )){
		build = version[2];
	}
	set_kb_item( name: NASLString( "www/", port, "/up.time" ), value: NASLString( vers, " under ", install ) );
	set_kb_item( name: "up.time/installed", value: TRUE );
	set_kb_item( name: "up.time/port", value: port );
	set_kb_item( name: "up.time/" + port + "/version", value: vers );
	if(build){
		set_kb_item( name: "up.time/" + port + "/build", value: build );
	}
	report = "Detected up.time version " + vers;
	if(build){
		report += " Build (" + build + ")";
	}
	report += "\nLocation: " + url + "\n";
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

