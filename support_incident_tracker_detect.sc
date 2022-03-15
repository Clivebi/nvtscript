if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100466" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SiT! Support Incident Tracker Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running SiT! Support Incident Tracker, a web based
  application which uses PHP and MySQL for tracking technical support calls/emails." );
	script_xref( name: "URL", value: "http://sitracker.org/wiki/Main_Page" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/tracker", "/support", "/sit", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "<meta name=\"GENERATOR\" content=\"SiT! Support Incident Tracker", string: buf, icase: TRUE ) && ContainsString( buf, "SiT! - Login" )){
		set_kb_item( name: "sit/installed", value: TRUE );
		version = "unknown";
		version_match = eregmatch( string: buf, pattern: "Support Incident Tracker v(([0-9.]+).?([a-zA-Z0-9]+))", icase: TRUE );
		if(!isnull( version_match[1] )){
			version = ereg_replace( pattern: " |-", string: version_match[1], replace: "." );
			concluded_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		set_kb_item( name: "www/" + port + "/support_incident_tracker", value: version );
		register_and_report_cpe( app: "SiT! Support Incident Tracker", ver: version, base: "cpe:/a:sitracker:support_incident_tracker:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: concluded_url );
		exit( 0 );
	}
}
exit( 0 );

