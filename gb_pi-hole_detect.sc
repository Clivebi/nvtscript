if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108342" );
	script_version( "2021-04-19T09:42:06+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-19 09:42:06 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-02-17 15:43:37 +0100 (Sat, 17 Feb 2018)" );
	script_name( "Pi-hole Ad-Blocker Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://pi-hole.net/" );
	script_tag( name: "summary", value: "HTTP based detection of the Pi-hole Ad-Blocker." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
for url in make_list( "/admin/",
	 "/" ) {
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Pi-hole Admin Console</title>" ) || egrep( string: buf, pattern: "<title>Pi-hole - [^<]+</title>", icase: FALSE ) || ContainsString( buf, "<a href=\"http://pi-hole.net\" class=\"logo\"" ) || ContainsString( buf, "<script src=\"scripts/pi-hole/js/footer.js\"></script>" ) || ContainsString( buf, "<!-- Pi-hole: A black hole for Internet advertisements" ) || ( ContainsString( buf, "Open Source Ad Blocker" ) && ContainsString( buf, "<small>Designed For Raspberry Pi</small>" ) ) )){
		install = "/";
		pihole_version = "unknown";
		web_version = "unknown";
		ftl_version = "unknown";
		concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "pi-hole/detected", value: TRUE );
		pihole_vers = eregmatch( string: buf, pattern: "(<b>Pi-hole Version ?</b> ?|<strong>Pi-hole</strong>[^>]+>)v([0-9.]+)" );
		if(pihole_vers[2]){
			pihole_version = pihole_vers[2];
		}
		web_vers = eregmatch( string: buf, pattern: "(<b>Web Interface Version ?</b> ?|<strong>Web Interface</strong>[^>]+>)v([0-9.]+)" );
		if(web_vers[2]){
			web_version = web_vers[2];
		}
		ftl_vers = eregmatch( string: buf, pattern: "(<b>FTL Version ?</b> ?(vDev \\()?|<strong>FTL</strong>[^>]+>)v([0-9.]+)" );
		if(ftl_vers[3]){
			ftl_version = ftl_vers[3];
		}
		pihole_cpe = build_cpe( value: pihole_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:pi-hole:" );
		if(!pihole_cpe){
			pihole_cpe = "cpe:/a:pi-hole:pi-hole";
		}
		web_cpe = build_cpe( value: web_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:web:" );
		if(!web_cpe){
			web_cpe = "cpe:/a:pi-hole:web";
		}
		ftl_cpe = build_cpe( value: ftl_version, exp: "^([0-9.]+)", base: "cpe:/a:pi-hole:ftl:" );
		if(!ftl_cpe){
			ftl_cpe = "cpe:/a:pi-hole:ftl";
		}
		register_product( cpe: pihole_cpe, location: install, port: port, service: "www" );
		register_product( cpe: web_cpe, location: install, port: port, service: "www" );
		register_product( cpe: ftl_cpe, location: install, port: port, service: "www" );
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, desc: "Pi-hole Ad-Blocker Detection", runs_key: "unixoide" );
		report = build_detection_report( app: "Pi-hole", version: pihole_version, install: install, cpe: pihole_cpe, concluded: pihole_vers[0], concludedUrl: concludedUrl );
		report += "\n\n";
		report += build_detection_report( app: "Pi-hole Web Interface", version: web_version, install: install, cpe: web_cpe, concluded: web_vers[0], concludedUrl: concludedUrl );
		report += "\n\n";
		report += build_detection_report( app: "Pi-hole FTL", version: ftl_version, install: install, cpe: ftl_cpe, concluded: ftl_vers[0], concludedUrl: concludedUrl );
		log_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

