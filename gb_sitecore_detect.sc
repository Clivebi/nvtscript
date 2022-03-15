if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108191" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-16 15:54:00 +0200 (Mon, 16 Oct 2017)" );
	script_name( "Sitecore CMS Detection" );
	script_tag( name: "summary", value: "Detection of Sitecore CMS.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
found = FALSE;
for dir in nasl_make_list_unique( "/", "/sitecore", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/login/", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "Sitecore" ) || ContainsString( res, "sitecore" ) ) && ( ContainsString( res, "<img id=\"BannerLogo\" src=\"/sitecore/login/logo.png\" alt=\"Sitecore Logo\"" ) || ContainsString( res, "<form method=\"post\" action=\"/sitecore/login" ) || ContainsString( res, "href=\"/sitecore/login/login.css\"" ) )){
		found = TRUE;
		version = "unknown";
		if(!ver = eregmatch( pattern: "Sitecore version.*\\(Sitecore ([0-9.]+)\\)", string: res )){
			if(!ver = eregmatch( pattern: "Sitecore\\.NET ([0-9.]+) \\(rev\\. ([0-9.]+) Hotfix ([0-9\\-]+)\\)", string: res )){
				if(!ver = eregmatch( pattern: "Sitecore\\.NET ([0-9.]+) \\(rev\\. ([0-9.]+)\\)", string: res )){
					ver = eregmatch( pattern: "Sitecore\\.NET ([0-9.]+)", string: res );
				}
			}
		}
		if(!isnull( ver[1] )){
			version = ver[1];
			concUrl = http_report_vuln_url( port: port, url: dir + "/login/", url_only: TRUE );
		}
		if(!isnull( ver[2] )){
			extra += "Revision: " + ver[2];
			set_kb_item( name: "sitecore/cms/" + port + "/revision", value: ver[2] );
		}
		if(!isnull( ver[3] )){
			extra += "\nHotfix: " + ver[3];
		}
		if(found){
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sitecore:cms:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:sitecore:cms";
			}
			set_kb_item( name: "sitecore/cms/installed", value: TRUE );
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Sitecore CMS", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concUrl, extra: extra ), port: port );
			exit( 0 );
		}
	}
}

