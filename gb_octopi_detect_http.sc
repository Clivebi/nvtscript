if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107343" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-10-11 16:21:34 +0200 (Thu, 11 Oct 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OctoPi Version Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of OctoPi Raspberry Pi distribution for 3D printers using HTTP." );
	script_xref( name: "URL", value: "https://octoprint.org/download/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
banner_type = "HTTP WWW-Authenticate banner / HTTP Interface";
SCRIPT_DESC = "OctoPi Version Detection (HTTP)";
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
buf = http_get_cache( item: "/", port: port );
if(IsMatchRegexp( banner, "^WWW-Authenticate: Basic realm=\"OctoPi (Interface)?\"" )){
	octopi_auth_found = TRUE;
}
if(octopi_auth_found || ( ContainsString( buf, "OctoPrint</title>" ) && ContainsString( buf, "plugin_octopi_support_version" ) )){
	install = "/";
	conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	version = "unknown";
	if( octopi_auth_found ){
		set_kb_item( name: "octopi/http/ " + port + "/auth", value: TRUE );
		set_kb_item( name: "octopi/http/auth", value: TRUE );
	}
	else {
		set_kb_item( name: "octopi/http/ " + port + "/noauth", value: TRUE );
		set_kb_item( name: "octopi/http/noauth", value: TRUE );
	}
	set_kb_item( name: "octopi/detected", value: TRUE );
	set_kb_item( name: "octopi/http/detected", value: TRUE );
	set_kb_item( name: "octopi/http/port", value: port );
	vers = eregmatch( pattern: "<span class=\"plugin_octopi_support_version\">([0-9.]+)</span>", string: buf, icase: TRUE );
	if(vers[1]){
		version = vers[1];
		set_kb_item( name: "octopi/http/" + port + "/version", value: version );
		set_kb_item( name: "octopi/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "octopi/http/" + port + "/concludedUrl", value: conclUrl );
	}
	os_register_and_report( os: "OctoPi Raspberry Pi distribution", version: vers[1], cpe: "cpe:/o:octoprint:octopi", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
}
exit( 0 );

