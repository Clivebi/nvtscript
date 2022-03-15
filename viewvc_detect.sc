if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100261" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-08-26 20:38:31 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ViewVC Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running ViewVC, a browser interface for CVS and
  Subversion version control repositories." );
	script_xref( name: "URL", value: "http://www.viewvc.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "ViewVC Detection";
port = http_get_port( default: 80 );
vcs = make_list( "/viewvc",
	 "/viewvc.cgi" );
for dir in nasl_make_list_unique( "/svn", "/scm", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for vc in vcs {
		url = NASLString( dir, vc, "/" );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(!buf){
			continue;
		}
		if(egrep( pattern: "Powered by <a[^>]+>ViewVC", string: buf, icase: TRUE ) || egrep( pattern: "<meta.*generator.*ViewVC", string: buf, icase: TRUE )){
			vers = NASLString( "unknown" );
			version = eregmatch( string: buf, pattern: "ViewVC ([0-9.]+[-dev]*)", icase: TRUE );
			if(!isnull( version[1] )){
				vers = chomp( version[1] );
			}
			tmp_version = NASLString( vers, " under ", install );
			set_kb_item( name: NASLString( "www/", port, "/viewvc" ), value: tmp_version );
			set_kb_item( name: "viewvc/detected", value: TRUE );
			cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+-?([a-z0-9]+)?)", base: "cpe:/a:viewvc:viewvc:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
			info = NASLString( "ViewVC Version '" );
			info += NASLString( vers );
			info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
			info += NASLString( install, "\\n" );
			log_message( port: port, data: info );
			exit( 0 );
		}
	}
}
exit( 0 );

