if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800525" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "TorrentTrader Classic Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.torrenttrader.org/" );
	script_tag( name: "summary", value: "This script detects the installed version of TorrentTrader
  Classic." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/ttc", "/", "/torrenttrader", "/torrent", "/tracker", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	installed = FALSE;
	version = "unknown";
	sndReq = http_get( item: dir + "/upload/account-login.php", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "TorrentTrader Classic" )){
		installed = TRUE;
		ver = eregmatch( pattern: "Classic ([a-zA-z]+)? ?v([0-9.]+)", string: rcvRes );
		if(ver[2] != NULL){
			if( ver[1] != NULL ){
				version = ver[2] + "." + ver[1];
			}
			else {
				version = ver[2];
			}
		}
	}
	if(version == "unknown"){
		rcvRes = http_get_cache( item: dir + "/index.php", port: port );
		if(egrep( pattern: "Powered by TorrentTrader Classic ([a-zA-z]+)? ?v([0-9.]+).*www.torrenttrader.org", string: rcvRes, icase: TRUE )){
			installed = TRUE;
			ver = eregmatch( pattern: "TorrentTrader Classic ([a-zA-z]+)? ?v([0-9.]+)", string: rcvRes );
			if(ver[2] != NULL){
				if( ver[1] != NULL ){
					version = ver[2] + "." + ver[1];
				}
				else {
					version = ver[2];
				}
			}
		}
	}
	if(installed){
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/TorrentTraderClassic", value: tmp_version );
		set_kb_item( name: "torrenttraderclassic/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:torrenttrader:torrenttrader_classic:" );
		if(isnull( cpe )){
			cpe = build_cpe( value: version, exp: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", base: "cpe:/a:torrenttrader:torrenttrader_classic:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:torrenttrader:torrenttrader_classic";
			}
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "TorrentTrader Classic", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

