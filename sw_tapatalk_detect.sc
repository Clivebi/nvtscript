if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111039" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-09-27 14:00:00 +0200 (Sun, 27 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Tapatalk Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "phpbb_detect.sc", "gb_simple_machines_forum_detect.sc", "vbulletin_detect.sc", "secpod_woltlab_burning_board_detect.sc", "sw_xenforo_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "www/can_host_tapatalk" );
	script_xref( name: "URL", value: "https://www.tapatalk.com/" );
	script_tag( name: "summary", value: "Checks whether Tapatalk is present on the
  target system and if so, tries to figure out the installed version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
cpe_list = make_list( "cpe:/a:phpbb:phpbb",
	 "cpe:/a:simplemachines:smf",
	 "cpe:/a:vbulletin:vbulletin",
	 "cpe:/a:xenforo:xenforo",
	 "cpe:/a:woltlab:burning_board" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!dir = get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
install = dir;
if(dir == "/"){
	dir = "";
}
url = dir + "/mobiquo/mobiquo.php";
buf = http_get_cache( item: url, port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "Tapatalk", string: buf, icase: TRUE )){
	version = "unknown";
	forumType = "unknown";
	cpeEdition = "";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	ver = eregmatch( pattern: "Current Tapatalk plugin version: ([0-9.]+)", string: buf );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	if( ContainsString( buf, "?plugin=phpbb" ) ){
		forumType = "phpBB";
		set_kb_item( name: "www/" + port + "/tapatalk/phpbb", value: version );
		set_kb_item( name: "tapatalk/phpbb/installed", value: TRUE );
		cpeEdition = ":::::phpbb";
	}
	else {
		if( ContainsString( buf, "?plugin=smf" ) ){
			ver = eregmatch( pattern: "Current Tapatalk plugin version: (sm20_|sm-2a_)([0-9.]+)", string: buf );
			if(!isnull( ver[2] )){
				version = ver[2];
			}
			forumType = "SMF";
			set_kb_item( name: "www/" + port + "/tapatalk/smf", value: version );
			set_kb_item( name: "tapatalk/smf/installed", value: TRUE );
			cpeEdition = ":::::smf";
		}
		else {
			if( ContainsString( buf, "?plugin=vbulletin" ) ){
				forumType = "vBulletin";
				set_kb_item( name: "www/" + port + "/tapatalk/vbulletin", value: version );
				set_kb_item( name: "tapatalk/vbulletin/installed", value: TRUE );
				cpeEdition = ":::::vbulletin";
			}
			else {
				if( ContainsString( buf, "?plugin=wbb" ) ){
					forumType = "WBB";
					set_kb_item( name: "www/" + port + "/tapatalk/wbb", value: version );
					set_kb_item( name: "tapatalk/wbb/installed", value: TRUE );
					cpeEdition = ":::::wotlab_burning_board";
				}
				else {
					if( ContainsString( buf, "?plugin=xnf" ) ){
						forumType = "XenForo";
						set_kb_item( name: "www/" + port + "/tapatalk/xenforo", value: version );
						set_kb_item( name: "tapatalk/xenforo/installed", value: TRUE );
						cpeEdition = ":::::xenforo";
					}
					else {
						set_kb_item( name: "www/" + port + "/tapatalk/unknown", value: version );
						set_kb_item( name: "tapatalk/unknown/installed", value: TRUE );
						cpeEdition = ":::::unknown";
					}
				}
			}
		}
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tapatalk:tapatalk:" );
	if( !cpe ) {
		cpe = "cpe:/a:tapatalk:tapatalk:" + cpeEdition;
	}
	else {
		cpe += cpeEdition;
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Tapatalk for " + forumType, version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: conclUrl ), port: port );
}
exit( 0 );

