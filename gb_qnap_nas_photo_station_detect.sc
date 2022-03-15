if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813164" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2018-05-03 19:51:43 +0530 (Thu, 03 May 2018)" );
	script_name( "QNAP QTS Photo Station Detection" );
	script_tag( name: "summary", value: "QNAP QTS Photo Station Detection.

  The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/port" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_kb_item( "qnap/port" )){
	exit( 0 );
}
for dir in make_list( "/photo",
	 "/photo/gallery",
	 "/gallery" ) {
	req = http_get_req( url: dir + "/", port: port, add_headers: make_array( "Accept-Encoding", "gzip, deflate" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 30." )){
		url = eregmatch( pattern: "Location: ([^\r\n]+)", string: res );
		if(url[1]){
			new_url = url[1];
			req = http_get_req( url: new_url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
				continue;
			}
		}
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "title>Photo Station</title" )){
		url = eregmatch( pattern: "'\\.js\\?([0-9.]+)", string: res );
		new_url = dir + "/lang/ENG.js?" + url[1];
		req = http_get_req( url: new_url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "QTS Login" ) && IsMatchRegexp( res, "COPYRIGHT=.*QNAP Systems" ) && ContainsString( res, "LANG_QTS" )){
			version = "unknown";
			set_kb_item( name: "QNAP/QTS/PhotoStation/detected", value: TRUE );
			url = dir + "/api/user.php";
			req = http_get_req( url: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "status" ) && ContainsString( res, "timestamp" )){
				vers = eregmatch( pattern: "<appVersion>([0-9.]+)</appVersion><appBuildNum>([0-9]+)<", string: res );
				baseQTSVersion = eregmatch( pattern: "<builtinFirmwareVersion>([0-9.]+)</builtinFirmwareVersion>", string: res );
				if(!isnull( vers[1] )){
					version = vers[1];
					concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
					set_kb_item( name: "QNAP/QTS/PhotoStation/version", value: version );
					if(!isnull( vers[2] )){
						build = vers[2];
						set_kb_item( name: "QNAP/QTS/PhotoStation/build", value: build );
					}
					if(baseQTSVersion[1]){
						baseQTSVer = baseQTSVersion[1];
						set_kb_item( name: "QNAP/QTS/PS/baseQTSVer", value: baseQTSVer );
					}
				}
				cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:photo_station:" );
				if(!cpe){
					cpe = "cpe:/a:qnap:photo_station";
				}
				register_product( cpe: cpe, location: dir, port: port, service: "www" );
				log_message( data: build_detection_report( app: "QNAP QTS Photo Station", version: version, install: dir, cpe: cpe, concludedUrl: concUrl, concluded: vers[0] ), port: port );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

