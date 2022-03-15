if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805609" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-06-01 12:25:40 +0530 (Mon, 01 Jun 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "OpenOffice Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of OpenOffice.

  The script logs in via ssh, searches for folder 'OpenOffice.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via command
  line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_family( "Product detection" );
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
if(!get_kb_item( "ssh/login/osx_name" )){
	close( sock );
	exit( 0 );
}
Ver = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "OpenOffice.app/Contents/Info CFBundleGetInfoString" ) );
Ver = eregmatch( pattern: "OpenOffice ([0-9.]+).*(Build:([0-9.]+))?", string: Ver );
if(isnull( Ver ) || ContainsString( Ver, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "OpenOffice/MacOSX/Version", value: Ver[1] );
cpe = build_cpe( value: Ver[1], exp: "^([0-9.]+)", base: "cpe:/a:openoffice:openoffice.org:" );
if(isnull( cpe )){
	cpe = "cpe:/a:openoffice:openoffice.org";
}
path = "/Applications/OpenOffice.app/";
register_product( cpe: cpe, location: path );
log_message( data: build_detection_report( app: "OpenOffice", version: Ver[1], install: "/Applications/OpenOffice.app", cpe: cpe, concluded: Ver[1] ) );

