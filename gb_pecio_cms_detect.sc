if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801443" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Pecio CMS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Pecio CMS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
cmsPort = http_get_port( default: 80 );
if(!http_can_host_php( port: cmsPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/pecio", "/pecio_cms", http_cgi_dirs( port: cmsPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: cmsPort );
	if(ContainsString( rcvRes, "content=\"pecio cms" )){
		cmsVer = eregmatch( pattern: "pecio cms ([0-9.]+)", string: rcvRes );
		if(cmsVer[1] != NULL){
			tmp_version = cmsVer[1] + " under " + install;
			set_kb_item( name: "www/" + cmsPort + "/Pecio_CMS", value: tmp_version );
			set_kb_item( name: "pecio_cms/detected", value: TRUE );
			log_message( data: "Pecio CMS version " + cmsVer[1] + " running at location " + install + " was detected on the host" );
			cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+)", base: "cpe:/a:pecio-cms:pecio_cms:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe );
			}
		}
	}
}

