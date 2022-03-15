if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103564" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-09-12 14:18:24 +0200 (Wed, 12 Sep 2012)" );
	script_name( "ownCloud Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "gb_nextcloud_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of ownCloud.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
for dir in nasl_make_list_unique( "/", "/oc", "/owncloud", "/ownCloud", "/OwnCloud", "/cloud", http_cgi_dirs( port: port ) ) {
	if(get_kb_item( "nextcloud/install/" + host + "/" + port + "/" + dir )){
		continue;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/status.php";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "You are accessing the server from an untrusted domain" )){
		req = http_get_req( port: port, url: url, host_header_use_ip: TRUE );
		buf = http_keepalive_send_recv( port: port, data: req );
	}
	if(!ContainsString( tolower( buf ), "egroupware" ) && !ContainsString( buf, "\"productname\":\"Nextcloud\"" ) && ( egrep( string: buf, pattern: "\"installed\":(\"true\"|true),(\"maintenance\":(\"true\"|true|\"false\"|false),)?(\"needsDbUpgrade\":(\"true\"|true|\"false\"|false),)?\"version\":\"([0-9.a]+)\",\"versionstring\":\"([0-9. a-zA-Z]+)\",\"edition\":\"(.*)\"" ) || ( ContainsString( buf, "You are accessing the server from an untrusted domain" ) && ContainsString( buf, ">ownCloud<" ) ) || ContainsString( buf, "\"productname\":\"ownCloud\"" ) )){
		version = "unknown";
		extra = NULL;
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		for authurl in make_list( dir + "/remote.php/dav",
			 dir + "/remote.php/webdav" ) {
			req = http_get( item: authurl, port: port );
			buf2 = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( buf2, "^HTTP/1\\.[01] 401" )){
				set_kb_item( name: "www/content/auth_required", value: TRUE );
				set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: authurl );
				break;
			}
		}
		ver = eregmatch( string: buf, pattern: "version\":\"([0-9.a]+)\",\"versionstring\":\"([0-9. a-zA-Z]+)\"", icase: TRUE );
		if(!isnull( ver[2] )){
			version = ereg_replace( pattern: " ", replace: "", string: ver[2] );
		}
		set_kb_item( name: "owncloud_or_nextcloud/installed", value: TRUE );
		set_kb_item( name: "owncloud/installed", value: TRUE );
		if(ContainsString( buf, "You are accessing the server from an untrusted domain" )){
			extra = "ownCloud is blocking full access to this server because the scanner is accessing the server via an untrusted domain.";
			extra += " To fix this configure the scanner to access the server on the expected domain.";
		}
		cpe = build_cpe( value: version, exp: "^([0-9.a]+)", base: "cpe:/a:owncloud:owncloud:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:owncloud:owncloud";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "ownCloud", version: version, install: install, cpe: cpe, extra: extra, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

