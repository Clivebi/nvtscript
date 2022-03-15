if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800399" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_name( "TWiki Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of TWiki.

The script sends a HTTP connection request to the server and attempts to detect the presence of TWiki and
to extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
cgidirs = nasl_make_list_unique( "/", "/twiki", "/wiki", http_cgi_dirs( port: port ) );
subdirs = make_list( "/",
	 "/bin",
	 "/do",
	 "/cgi-bin" );
for cgidir in cgidirs {
	for subdir in subdirs {
		if(cgidir == "/cgi-bin" && subdir == "/cgi-bin"){
			continue;
		}
		if(cgidir != "/" && subdir == "/"){
			subdir = "";
		}
		if(cgidir == "/"){
			cgidir = "";
		}
		dirs = nasl_make_list_unique( dirs, cgidir + subdir );
	}
}
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/view/TWiki/WebHome", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: FALSE );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( egrep( pattern: "[p|P]owered by TWiki", string: rcvRes ) || ContainsString( rcvRes, "This site is powered by the TWiki collaboration platform" ) )){
		if(ContainsString( rcvRes, "(edit)</title>" ) || ContainsString( rcvRes, "( vs. )</title>" ) || ContainsString( rcvRes, "This Wiki topic does not exist" ) || ContainsString( dir, "/bin/view/TWiki/bin" ) || ContainsString( dir, "/bin/rdiff/TWiki/bin" )){
			continue;
		}
		version = "unknown";
		exp = "^([0-9.]+)";
		ver = eregmatch( pattern: "TWiki-([0-9.]+),", string: rcvRes );
		if( !isnull( ver[1] ) ){
			version = ver[1];
		}
		else {
			ver = eregmatch( pattern: "This site is running TWiki version <strong>([a-zA-Z0-9 ]+)</strong>", string: rcvRes );
			if(!isnull( ver[1] )){
				version = ereg_replace( pattern: " ", string: ver[1], replace: "." );
				exp = "^([a-zA-Z0-9.]+)";
			}
		}
		set_kb_item( name: "twiki/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: exp, base: "cpe:/a:twiki:twiki:" );
		if(!cpe){
			cpe = "cpe:/a:twiki:twiki";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "TWiki", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

