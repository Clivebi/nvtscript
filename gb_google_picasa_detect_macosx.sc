if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806629" );
	script_version( "$Revision: 11284 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:30:56 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-26 13:02:06 +0530 (Thu, 26 Nov 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Google Picasa Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detection of installed version
  of Google Picasa.

  The script logs in via ssh, searches for folder 'Picasa.app' and queries
  the related 'info.plist' file for string 'CFBundleVersion' via command
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
picVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "/Picasa.app/Contents/Info CFBundleVersion" ) );
if(isnull( picVer ) || ContainsString( picVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "picVer/MacOSX/Version", value: picVer );
cpe = build_cpe( value: picVer, exp: "^([0-9.]+)", base: "cpe:/a:google:picasa:" );
if(isnull( cpe )){
	cpe = "cpe:/a:google:picasa:";
}
path = "/Applications/Picasa.app/";
register_product( cpe: cpe, location: path );
log_message( data: build_detection_report( app: "Google Picasa", version: picVer, install: path, cpe: cpe, concluded: picVer ) );

