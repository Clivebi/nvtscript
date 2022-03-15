if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100597" );
	script_version( "2020-10-05T09:43:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-05 09:43:10 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-04-22 20:18:17 +0200 (Thu, 22 Apr 2010)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HCL / IBM / Lotus Domino Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of HCL Domino (formerly Lotus/IBM Domino)." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
domino_ver = "unknown";
debug = 0;
versionFiles = make_array( "/download/filesets/l_LOTUS_SCRIPT.inf", "Version=([0-9FP.]+)", "/download/filesets/n_LOTUS_SCRIPT.inf", "Version=([0-9FP.]+)", "/download/filesets/l_SEARCH.inf", "Version=([0-9FP.]+)", "/download/filesets/n_SEARCH.inf", "Version=([0-9FP.]+)", "/download/filesets/l_SHIMMER9.inf", "Version=([0-9FP.]+)", "/download/filesets/l_SHIMMER8_5_en.inf", "Version=([0-9FP.]+)", "/download/filesets/l_SHIMMER8_en.inf", "Version=([0-9FP.]+)", "/download/filesets/l_SHIMMER8_5.inf", "Version=([0-9FP.]+)", "/download/filesets/l_SHIMMER8.inf", "Version=([0-9FP.]+)", "/download/filesets/n_SHIMMER9.inf", "Version=([0-9FP.]+)", "/download/filesets/n_SHIMMER8_5_en.inf", "Version=([0-9FP.]+)", "/download/filesets/n_SHIMMER8_en.inf", "Version=([0-9FP.]+)", "/download/filesets/n_SHIMMER8_5.inf", "Version=([0-9FP.]+)", "/download/filesets/n_SHIMMER8.inf", "Version=([0-9FP.]+)", "/download/filesets/n_MAPI.inf", "Version=([0-9FP.]+)", "/download/filesets/l_English.inf", "Version=([0-9FP.]+)", "/download/filesets/n_DOLBASE.inf", "Version=([0-9FP.]+)", "/iNotes/Forms5.nsf", "<!-- Domino Release ([0-9FP.]+)", "/iNotes/Forms6.nsf", "<!-- Domino Release ([0-9FP.]+)", "/iNotes/Forms7.nsf", "<!-- Domino Release ([0-9FP.]+)", "/iNotes/Forms8.nsf", "<!-- Domino Release ([0-9FP.]+)", "/iNotes/Forms85.nsf", "<!-- Domino Release ([0-9FP.]+)", "/iNotes/Forms9.nsf", "<!-- Domino Release ([0-9FP.]+)", "/help/readme.nsf?OpenAbout", "Lotus Notes/Domino ([0-9FP.]+)", "/api", "\\s*\"name\":\"Core\",\\s*\"enabled\":[^,]*,\\s*\"version\":\"([0-9FP.]+)(\\.v[0-9]+)?", "/homepage.nsf", ">Domino Administrator ([0-9FP.]+) Help</" );
cgis = "/domcfg.nsf";
final_ver = "unknown";
extra = "";
port = http_get_port( default: 443 );
host = http_host_name( dont_add_port: TRUE );
nsfList = http_get_kb_file_extensions( port: port, host: host, ext: "nsf" );
tmpCgis = nasl_make_list_unique( "/", http_cgi_dirs( port: port ) );
for tmpCgi in tmpCgis {
	if(tmpCgi == "/"){
		tmpCgi = "";
	}
	cgis = make_list( cgis,
		 tmpCgi + "/domcfg.nsf" );
}
if( nsfList ){
	nsfFiles = nasl_make_list_unique( nsfList, "/nonexistent.nsf", cgis );
}
else {
	nsfFiles = nasl_make_list_unique( "/nonexistent.nsf", cgis );
}
for nsfFile in nsfFiles {
	banner = http_get_remote_headers( port: port, file: nsfFile );
	req = http_get( item: nsfFile, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(( banner && ( ContainsString( banner, "Lotus-Domino" ) || ContainsString( banner, "Lotus Domino" ) ) ) || ( ContainsString( res, "src=\"/domcfg.nsf/" ) && ( ContainsString( res, "self._domino_name" ) || ContainsString( res, "Web Server Configuration" ) ) ) || ContainsString( res, "src=\"/webstart.nsf/IBMLogo.gif" ) || ContainsString( res, "HTTP Web Server: IBM Notes Exception - File does not exist" )){
		concludedUrl = http_report_vuln_url( port: port, url: nsfFile, url_only: TRUE );
		domino_ver = "unknown";
		installed = TRUE;
		version = eregmatch( pattern: "Lotus-Domino.{1,2}Release[- ]([0-9.]+)", string: banner );
		inst = eregmatch( pattern: "(.*/)(.*\\.nsf)", string: nsfFile );
		if( inst[1] ){
			install = inst[1];
		}
		else {
			install = "/";
		}
		set_kb_item( name: "www/domino/" + port + "/dir", value: install );
		if( !isnull( version[1] ) ){
			domino_ver = version[1];
			concluded = version[0];
			extra += "\n" + http_report_vuln_url( port: port, url: nsfFile, url_only: TRUE ) + " : " + version[1];
		}
		else {
			extra += "\n" + http_report_vuln_url( port: port, url: nsfFile, url_only: TRUE ) + " : unknown";
			for file in keys( versionFiles ) {
				dir = install;
				if(dir == "/"){
					dir = "";
				}
				url = dir + file;
				req = http_get_req( port: port, url: url, user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0" );
				res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
				if(!ContainsString( res, "Version=" ) && !ContainsString( res, "Domino Release" ) && !ContainsString( res, ">Domino Administrator" ) && ( !ContainsString( res, "\"services\":[" ) && !ContainsString( res, "\"href\":\"\\/api\\/core\"" ) && !ContainsString( res, "\"name\":\"Core\"," ) )){
					ref = eregmatch( pattern: "src=\"(" + url + "/iNotes/Proxy/\\?OpenDocument&Form=l_SessionFrame&[^\"]+)", string: res );
					if(!isnull( ref[1] )){
						req = http_get( port: port, item: ref[1] );
						res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
						url = ref[1];
					}
				}
				if(ContainsString( res, "Version=" ) || ContainsString( res, "Domino Release" ) || ContainsString( res, ">Domino Administrator" ) || ( ContainsString( res, "\"services\":[" ) || ContainsString( res, "\"href\":\"\\/api\\/core\"" ) || ContainsString( res, "\"name\":\"Core\"," ) )){
					version = eregmatch( pattern: versionFiles[file], string: res );
					if( !isnull( version[1] ) ){
						if(ContainsString( file, "/api" ) && version[2]){
							version[2] = ereg_replace( string: version[2], pattern: "\\.v([0-9]+)", replace: "FP\\1" );
							version[1] += version[2];
						}
						extra += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " : " + version[1];
						if(domino_ver == "unknown"){
							domino_ver = version[1];
							concluded = version[0];
						}
						tmp_ver = version[1];
						if(debug){
							display( "Current detected version in " + url + ": " + tmp_ver + ", previous version: " + domino_ver + "\n" );
						}
						if(version_is_greater( version: tmp_ver, test_version: domino_ver )){
							domino_ver = tmp_ver;
							concluded = version[0];
						}
					}
					else {
						extra += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " : unknown";
					}
				}
			}
			if(concluded){
				version[0] = concluded;
			}
		}
		if(domino_ver != "unknown"){
			final_ver = domino_ver;
		}
	}
	if(installed && final_ver != "unknown"){
		break;
	}
}
if(installed){
	set_kb_item( name: "hcl/domino/detected", value: TRUE );
	set_kb_item( name: "hcl/domino/http/port", value: port );
	final_ver = str_replace( string: final_ver, find: "FP", replace: "." );
	final_ver = ereg_replace( string: final_ver, pattern: "( )?HF", replace: ".HF" );
	set_kb_item( name: "hcl/domino/http/" + port + "/version", value: final_ver );
	if(extra){
		set_kb_item( name: "hcl/domino/http/" + port + "/concluded", value: extra );
	}
}
exit( 0 );

