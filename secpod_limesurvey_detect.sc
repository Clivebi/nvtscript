if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900352" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "LimeSurvey Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of LimeSurvey.

  The script sends a connection request to the server and attempts to detect LimeSurvey and its version." );
	script_xref( name: "URL", value: "https://www.limesurvey.org" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/limesurvey", "/phpsurveyor", "/survey", "/PHPSurveyor", http_cgi_dirs( port: port ) ) {
	rep_dir = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(!res){
		continue;
	}
	if( IsMatchRegexp( res, "meta name=\"generator\" content=\"LimeSurvey https?://(www\\.)?limesurvey\\.org\"" ) || ContainsString( res, "<a href='#' data-limesurvey-lang='" ) ){
		version = "unknown";
		url = dir + "/docs/release_notes.txt";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "Changes from [^)]+\\)? to ([0-9.]+)(\\+|-?[0-9a-zA-Z.]+)?", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			if(!isnull( vers[2] )){
				version += vers[2];
			}
			concUrl = url;
		}
		set_kb_item( name: "limesurvey/installed", value: TRUE );
		cpe = "cpe:/a:limesurvey:limesurvey";
		if(version != "unknown"){
			if( !isnull( vers[2] ) ){
				update_version = ereg_replace( string: vers[2], pattern: "[-.]", replace: "" );
				cpe += ":" + vers[1] + ":" + update_version;
			}
			else {
				cpe += ":" + vers[1];
			}
		}
		register_product( cpe: cpe, location: rep_dir, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LimeSurvey", version: version, install: rep_dir, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
	else {
		if(ContainsString( res, "You have not provided a survey identification number" )){
			version = "unknown";
			url = dir + "/docs/release_notes_and_upgrade_instructions.txt";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			vers = eregmatch( pattern: "Changes from ([0-9.]+)(\\+|-?[0-9a-zA-Z.]+)? to ([0-9.]+)(\\+|-?[0-9a-zA-Z.]+)?", string: res );
			if(!isnull( vers[3] )){
				version = vers[3];
				if(!isnull( vers[4] )){
					version += vers[4];
				}
				concUrl = url;
			}
			set_kb_item( name: "limesurvey/installed", value: TRUE );
			cpe = "cpe:/a:limesurvey:limesurvey";
			if(version != "unknown"){
				if( !isnull( vers[4] ) ){
					update_version = ereg_replace( string: vers[4], pattern: "[-.]", replace: "" );
					cpe += ":" + vers[3] + ":" + update_version;
				}
				else {
					cpe += ":" + vers[3];
				}
			}
			register_product( cpe: cpe, location: rep_dir, port: port, service: "www" );
			log_message( data: build_detection_report( app: "LimeSurvey", version: version, install: rep_dir, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
	}
}
exit( 0 );

