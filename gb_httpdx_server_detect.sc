if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800960" );
	script_version( "2020-08-25T06:34:32+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:34:32 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "httpdx Server Version Detection" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/www", 80, "Services/ftp", 21, 990 );
	script_mandatory_keys( "www_or_ftp/httpdx/detected" );
	script_tag( name: "summary", value: "Detection of httpdx Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
ftpPorts = ftp_get_ports();
for port in ftpPorts {
	banner = ftp_get_banner( port: port );
	if(!banner || !ContainsString( banner, "httpdx" )){
		continue;
	}
	set_kb_item( name: "httpdx/installed", value: TRUE );
	vers = "unknown";
	install = port + "/tcp";
	httpdxVer = eregmatch( pattern: "httpdx.([0-9.]+[a-z]?)", string: banner );
	if(!isnull( httpdxVer[1] )){
		set_kb_item( name: "httpdx/" + port + "/Ver", value: httpdxVer[1] );
		vers = httpdxVer[1];
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+([a-z]+)?)", base: "cpe:/a:jasper:httpdx:" );
	if(!cpe){
		cpe = "cpe:/a:jasper:httpdx";
	}
	register_product( cpe: cpe, location: install, port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "httpdx", version: vers, install: install, cpe: cpe, concluded: httpdxVer[0] ), port: port );
}
if(http_is_cgi_scan_disabled()){
	exit( 0 );
}
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && ContainsString( banner, "httpdx/" )){
	vers = "unknown";
	install = "/";
	httpdxVer = eregmatch( pattern: "httpdx.([0-9.]+[a-z]?)", string: banner );
	if(!isnull( httpdxVer[1] )){
		set_kb_item( name: "httpdx/" + port + "/Ver", value: httpdxVer[1] );
		vers = httpdxVer[1];
	}
	set_kb_item( name: "httpdx/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+([a-z]+)?)", base: "cpe:/a:jasper:httpdx:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:jasper:httpdx";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "httpdx", version: vers, install: install, cpe: cpe, concluded: httpdxVer[0] ), port: port );
}
exit( 0 );

