if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902533" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Cybozu Products Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running Cybozu Products version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/scripts", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for path in make_list( "",
		 "/cbgrn",
		 "/garoon",
		 "/grn" ) {
		install = dir + path;
		req = http_get( item: install + "/grn.exe", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Cybozu" ) && ContainsString( res, "Garoon" )){
			version = "unknown";
			ver = eregmatch( pattern: "Version ([0-9.]+)", string: res );
			if(ver[1]){
				version = ver[1];
			}
			tmp_version = version + " under " + install;
			set_kb_item( name: "www/" + port + "/CybozuGaroon", value: tmp_version );
			set_kb_item( name: "CybozuGaroon/Installed", value: TRUE );
			set_kb_item( name: "cybozu_products/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cybozu:garoon:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:cybozu:garoon";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Cybozu Garoon", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		}
	}
	for path in make_list( "",
		 "/cbag",
		 "/office",
		 "/cgi-bin/cbag" ) {
		for file in make_list( "/ag.exe",
			 "/ag.cgi" ) {
			install = dir + path;
			req = http_get( item: install + file, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Cybozu" ) && ContainsString( res, "Office" )){
				version = "unknown";
				ver = eregmatch( pattern: "Office Version ([0-9.]+)", string: res );
				if(ver[1]){
					version = ver[1];
				}
				tmp_version = version + " under " + install;
				set_kb_item( name: "CybozuOffice/Installed", value: TRUE );
				set_kb_item( name: "www/" + port + "/CybozuOffice", value: tmp_version );
				set_kb_item( name: "cybozu_products/detected", value: TRUE );
				cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cybozu:office:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:cybozu:office";
				}
				register_product( cpe: cpe, location: install, port: port, service: "www" );
				log_message( data: build_detection_report( app: "Cybozu Office", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
			}
		}
	}
	for path in make_list( "",
		 "/cbdb",
		 "/dezie" ) {
		install = dir + path;
		req = http_get( item: install + "/db.exe", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Cybozu" ) && ContainsString( res, "Dezie" )){
			version = "unknown";
			ver = eregmatch( pattern: "Version ([0-9.]+)", string: res );
			if(ver[1]){
				version = ver[1];
			}
			tmp_version = version + " under " + install;
			set_kb_item( name: "CybozuDezie/Installed", value: TRUE );
			set_kb_item( name: "www/" + port + "/CybozuDezie", value: tmp_version );
			set_kb_item( name: "cybozu_products/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cybozu:dezie:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:cybozu:dezie";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Cybozu Dezie", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		}
	}
	for path in make_list( "",
		 "/cbmw",
		 "/mailwise" ) {
		install = dir + path;
		req = http_get( item: install + "/mw.exe", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Cybozu" ) && ContainsString( res, "mailwise" )){
			version = "unknown";
			ver = eregmatch( pattern: "Version ([0-9.]+)", string: res );
			if(ver[1]){
				version = ver[1];
			}
			tmp_version = version + " under " + install;
			set_kb_item( name: "CybozuMailWise/Installed", value: TRUE );
			set_kb_item( name: "www/" + port + "/CybozuMailWise", value: tmp_version );
			set_kb_item( name: "cybozu_products/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cybozu:mailwise:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:cybozu:mailwise";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Cybozu MailWise", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		}
	}
}
exit( 0 );

