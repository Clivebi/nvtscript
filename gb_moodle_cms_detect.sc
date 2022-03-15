if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800239" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Moodle CMS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://moodle.org/" );
	script_tag( name: "summary", value: "This host is running moodle.
  Moodle is a Course Management System (CMS), also known as a Learning
  Management System (LMS) or a Virtual Learning Environment (VLE). It
  is a Free web application that educators can use to create effective
  online learning sites." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/moodle", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(egrep( pattern: "^Set-Cookie: MoodleSession", string: rcvRes ) || egrep( pattern: "<a [^>]*href=\"http://moodle\\.org/\"[^>]*><img [^>]*src=\"pix/moodlelogo.gif\"", string: rcvRes )){
		set_kb_item( name: "moodle/detected", value: TRUE );
		version = "unknown";
		ver = eregmatch( string: rcvRes, pattern: "title=.Moodle ([0-9.]+)\\+*.*[(Build: 0-9)]*" );
		if( !isnull( ver[1] ) ){
			version = ver[1];
		}
		else {
			req = http_get( port: port, item: dir + "/admin/environment.xml" );
			resp = http_keepalive_send_recv( port: port, data: req );
			for(;TRUE;){
				ver = eregmatch( string: resp, pattern: "<MOODLE version=\"([0-9.]+)\"" );
				if(isnull( ver[1] )){
					break;
				}
				final_ver = ver;
				resp = ereg_replace( pattern: "<MOODLE version=\"" + ver[1] + "\"", string: resp, replace: "None" );
			}
			ver = final_ver;
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/moodle", value: tmp_version );
		set_kb_item( name: "Moodle/Version", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:moodle:moodle:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:moodle:moodle";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "moodle", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

