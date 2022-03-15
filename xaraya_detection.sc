if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19426" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Detects Xaraya version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 Josh Zlatin-Amishav" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.xaraya.com/" );
	script_tag( name: "summary", value: "The remote web server contains a web application framework written in
  PHP. This script detects whether the remote host is running Xaraya and
  extracts the version number and location if found." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/xaraya", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(!res){
		continue;
	}
	if(ContainsString( res, "^Set-Cookie: XARAYASID=" ) || ContainsString( res, "^X-Meta-Generator: Xaraya ::" ) || egrep( string: res, pattern: "div class=\"xar-(alt|block-.+|menu-.+|norm)\"" )){
		pat = "meta name=\"Generator\" content=\"Xaraya :: ([^\"]+)";
		matches = egrep( pattern: pat, string: res );
		if(matches){
			for match in split( matches ) {
				ver = eregmatch( pattern: pat, string: match );
				if(!isnull( ver )){
					ver = ver[1];
					info = NASLString( "Xaraya version ", ver, " is installed on the remote host\\nunder the path ", install, "." );
					break;
				}
			}
		}
		if(isnull( ver )){
			ver = "unknown";
			info = NASLString( "An unknown version of Xaraya is installed on the remote host\\nunder the path ", install, "." );
		}
		set_kb_item( name: "www/" + port + "/xaraya", value: ver + " under " + install );
		report = "\n\nPlugin output :\n\n" + info;
		log_message( port: port, data: report );
		exit( 0 );
	}
}

