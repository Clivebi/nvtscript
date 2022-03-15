if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113643" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-02-20 16:55:55 +0100 (Thu, 20 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Movable Type Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether Movable Type is present
  on the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.movabletype.com/" );
	exit( 0 );
}
CPE = "cpe:/a:sixapart:movabletype:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	buf = http_get_cache( port: port, item: dir );
	if(!IsMatchRegexp( buf, "<meta name=\"generator\" content=\"Movable Type" ) && !IsMatchRegexp( buf, ">Powered by Movable Type" )){
		continue;
	}
	set_kb_item( name: "sixapart/movabletype/detected", value: TRUE );
	version = "unknown";
	beta = "";
	ver = eregmatch( pattern: "<meta name=\"generator\" content=\"Movable Type( Publishing Platform| Pro)? ([0-9.]+)-?(beta[0-9-]+)?", string: buf, icase: TRUE );
	if( !isnull( ver[2] ) ){
		version = ver[2];
		if(!isnull( ver[3] )){
			beta = ver[3];
		}
	}
	else {
		ver = eregmatch( pattern: ">Powered by Movable Type( Publishing Platform| Pro)? ([0-9.]+)-?(beta[0-9-]+)?", string: buf, icase: TRUE );
		if(!isnull( ver[2] )){
			version = ver[2];
			if(!isnull( ver[3] )){
				beta = ver[3];
			}
		}
	}
	if(beta != ""){
		beta = ereg_replace( string: beta, pattern: "-", replace: "." );
		version += "-" + beta;
	}
	register_and_report_cpe( app: "Movable Type", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)-?(beta[0-9.]+)?", insloc: dir, regPort: port, regService: "www", conclUrl: http_report_vuln_url( port: port, url: dir, url_only: TRUE ) );
	exit( 0 );
}
exit( 0 );

