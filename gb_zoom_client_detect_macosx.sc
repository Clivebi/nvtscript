if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814355" );
	script_version( "2021-10-01T07:34:59+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-01 07:34:59 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2018-12-06 18:04:33 +0530 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Zoom Client Detection (Mac OS X SSH Login)" );
	script_tag( name: "summary", value: "SSH login-based detection of the Zoom Client." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
zoomVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/zoom.us.app/Contents/Info CFBundleShortVersionString" ) );
close( sock );
if(isnull( zoomVer ) || ContainsString( zoomVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "zoom/client/detected", value: TRUE );
set_kb_item( name: "zoom/client/mac/detected", value: TRUE );
cpe = build_cpe( value: zoomVer, exp: "^([0-9.]+)", base: "cpe:/a:zoom:zoom:" );
if(!cpe){
	cpe = "cpe:/a:zoom:zoom";
}
cpe2 = build_cpe( value: zoomVer, exp: "^([0-9.]+)", base: "cpe:/a:zoom:meetings:" );
if(!cpe2){
	cpe2 = "cpe:/a:zoom:meetings";
}
register_product( cpe: cpe, location: "/Applications/zoom.us.app", service: "ssh-login", port: 0 );
register_product( cpe: cpe2, location: "/Applications/zoom.us.app", service: "ssh-login", port: 0 );
report = build_detection_report( app: "Zoom Client", version: zoomVer, install: "/Applications/zoom.us.app", cpe: cpe, concluded: zoomVer );
log_message( port: 0, data: report );
exit( 0 );

