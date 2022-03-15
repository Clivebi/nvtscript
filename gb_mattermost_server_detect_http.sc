if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108464" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-17 09:44:56 +0200 (Mon, 17 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Mattermost Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8065 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the server
  and attempts to identify an installed Webapp of a Mattermost Server and its version
  from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
rootInstalled = FALSE;
port = http_get_port( default: 8065 );
for dir in nasl_make_list_unique( "/", "/mattermost", http_cgi_dirs( port: port ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(( ContainsString( buf, "<title>Mattermost</title>" ) && ( ContainsString( buf, "content=Mattermost>" ) || ContainsString( buf, "content='Mattermost'>" ) ) ) || ContainsString( buf, "To use Mattermost, please enable JavaScript." ) || ContainsString( buf, "<h2>Cannot connect to Mattermost</h2>" ) || ContainsString( buf, "re having trouble connecting to Mattermost. If refreshing this page (Ctrl+R or Command+R) does not work, please verify that your computer is connected to the internet." )){
		if(install == "/"){
			rootInstalled = TRUE;
		}
		version = "unknown";
		url = dir + "/api/v4/config/client?format=old";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		ver = eregmatch( pattern: "\",\"BuildNumber\":\"([^\"]+)\",\"", string: res );
		if(!isnull( ver[1] )){
			version = ereg_replace( pattern: "-", string: ver[1], replace: "." );
			concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			url = dir + "/api/v3/users/initial_load";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			ver = eregmatch( pattern: "\",\"BuildNumber\":\"([^\"]+)\",\"", string: res );
			if(!isnull( ver[1] )){
				version = ereg_replace( pattern: "-", string: ver[1], replace: "." );
				concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			fullver = egrep( pattern: "^X-Version-Id: [^\\r\\n]+", string: buf );
			if(fullver){
				fullver = chomp( fullver );
				ver = eregmatch( pattern: "^X-Version-Id: (.*)", string: fullver );
				if(ver[1]){
					_fullver = split( buffer: ver[1], sep: ".", keep: FALSE );
					if( max_index( _fullver ) == 4 ){
						version = _fullver[0] + "." + _fullver[1] + "." + _fullver[2];
					}
					else {
						if(max_index( _fullver ) == 8){
							version = _fullver[3] + "." + _fullver[4] + "." + _fullver[5];
						}
					}
					version = ereg_replace( pattern: "-", string: version, replace: "." );
				}
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.a-z]+)", base: "cpe:/a:mattermost:mattermost_server:" );
		if(!cpe){
			cpe = "cpe:/a:mattermost:mattermost_server";
		}
		set_kb_item( name: "mattermost_server/detected", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Mattermost Server", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concludedUrl ), port: port );
	}
}
exit( 0 );

