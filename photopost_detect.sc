if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100285" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Photopost Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 LSS / Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running Photopost, a photo sharing gallery software." );
	script_xref( name: "URL", value: "http://www.photopost.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Photopost Detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/photopost", "/photos", "/gallery", "/photo", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	match = egrep( pattern: "Powered by[^>]*>(<font[^>]*>)?PhotoPost", string: buf, icase: TRUE );
	if(match){
		match = egrep( pattern: "Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)", string: buf, icase: TRUE );
		if(match){
			item = eregmatch( pattern: "Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)", string: match, icase: TRUE );
		}
		ver = item[2];
		if(!ver){
			ver = "unknown";
		}
		tmp_version = NASLString( ver, " under ", install );
		set_kb_item( name: NASLString( "www/", port, "/photopost" ), value: tmp_version );
		set_kb_item( name: "photopost/detected", value: TRUE );
		cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:photopost:photopost_php_pro:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		info += ver + " under " + install + "\n";
		n++;
	}
}
if(!n){
	exit( 0 );
}
info = "The following version(s) of PhotoPost were detected: " + "\n\n" + info;
log_message( port: port, data: info );
exit( 0 );

