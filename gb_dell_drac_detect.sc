if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103680" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Dell Remote Access Controller Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Dell Remote Access Controller.

  The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
url = "/restgui/locale/personality/personality_en.json";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "\"app_name\": \"Integrated Remote Access Controller 9\"" )){
	version = "unknown";
	url = "/sysmgmt/2015/bmc/info";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "\"FwVer\":\"([0-9.]+)\"", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:idrac9:" );
	if(!cpe){
		cpe = "cpe:/a:dell:idrac9";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell iDRAC9", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
url = "/login.html";
req = http_get_req( port: port, url: "/login.html", add_headers: make_array( "Accept-Encoding", "gzip, deflate" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "<title id=\"titleLbl_id\"></title>" ) && ContainsString( res, "log_thisDRAC" )){
	version = "unknown";
	url = "/session?aimGetProp=fwVersionFull";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "fwVersionFull\" :\"([^(\" ]+)( \\(Build ([0-9]+)\\))?", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
		if(!isnull( vers[3] )){
			build = vers[3];
			set_kb_item( name: "dell_idrac/build", value: build );
			extra = "Build:  " + build;
		}
	}
	set_kb_item( name: "dell_idrac/installed", value: TRUE );
	req = http_post_put_req( port: port, url: "/data?get=prodServerGen" );
	res = http_keepalive_send_recv( port: port, data: req );
	generation = "";
	gen = eregmatch( pattern: "<prodServerGen>([^<]+)", string: res );
	if(!isnull( gen[1] )){
		if( gen[1] == "12G" ){
			generation = "7";
			set_kb_item( name: "dell_idrac/generation", value: generation );
		}
		else {
			if(gen[1] == "13G"){
				generation = "8";
				set_kb_item( name: "dell_idrac/generation", value: generation );
			}
		}
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:idrac" + generation + ":" );
	if(!cpe){
		cpe = "cpe:/a:dell:idrac" + generation;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell iDRAC" + generation, version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
urls = make_array();
urls["/cgi/lang/en/login.xsl"] = "Dell Remote Access Controller ([0-9]{1})";
urls["/public/about.html"] = "Integrated Dell Remote Access Controller ([0-9]{1})";
urls["/cgi/about"] = "Dell Remote Access Controller ([0-9]{1})";
urls["/Applications/dellUI/Strings/EN_about_hlp.htm"] = "Integrated Dell Remote Access Controller ([0-9]{1})";
info_url[4] = make_list( "/cgi/about" );
info_url_regex[4] = make_list( "var s_build = \"([^\"]+)\"" );
info_url[5] = make_list( "/cgi-bin/webcgi/about" );
info_url_regex[5] = make_list( "<FirmwareVersion>([^<]+)</FirmwareVersion>" );
info_url[6] = make_list( "/public/about.html",
	 "/Applications/dellUI/Strings/EN_about_hlp.htm" );
info_url_regex[6] = make_list( "Version ([^<]+)<br>",
	 "var fwVer = \"([^\"]+)\";",
	 "Version ([0-9.]+)" );
info_url[7] = make_list( "/public/about.html" );
info_url_regex[7] = make_list( "var fwVer = \"([^(\"]+)\";" );
for url in keys( urls ) {
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(!egrep( pattern: urls[url], string: buf )){
		continue;
	}
	version = eregmatch( pattern: urls[url], string: buf );
	if(isnull( version[1] )){
		continue;
	}
	set_kb_item( name: "dell_idrac/installed", value: TRUE );
	generation = version[1];
	if(!isnull( version[1] )){
		set_kb_item( name: "dell_idrac/generation", value: generation );
	}
	iv = int( version[1] );
	iv_urls = info_url[iv];
	if(iv_urls){
		for iv_url in iv_urls {
			req = http_get( item: iv_url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(!buf || ContainsString( buf, "HTTP/1\\.1 404" )){
				continue;
			}
			for iur in info_url_regex[iv] {
				fw_version = eregmatch( pattern: iur, string: buf );
				if(!isnull( fw_version[1] )){
					fw = fw_version[1];
					concUrl = iv_url;
					break;
				}
			}
			if(fw){
				if(ContainsString( fw, "(Build" )){
					f = eregmatch( pattern: "^([0-9.]+)\\(Build ([0-9]+)\\)", string: fw );
					if(!isnull( f[1] )){
						fw = f[1];
					}
					if(!isnull( f[2] )){
						set_kb_item( name: "dell_idrac/build", value: f[2] );
					}
					extra = "Build:  " + f[2];
				}
				break;
			}
		}
	}
	cpe = build_cpe( value: fw, exp: "^([0-9.]+)", base: "cpe:/a:dell:idrac" + generation + ":" );
	if(!cpe){
		cpe = "cpe:/a:dell:idrac" + generation;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell iDRAC" + generation, version: fw, install: "/", cpe: cpe, concluded: fw_version[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

