if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902680" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-05-21 15:49:33 +0530 (Mon, 21 May 2012)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Google SketchUp Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Google SketchUp.

The script logs in via ssh, searches for folder 'SketchUp.app' and
queries the related 'info.plist' file for string 'CFBundleVersion' via command
line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
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
for ver in make_list( "5",
	 "6",
	 "7",
	 "8" ) {
	gsVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Google\\ SketchUp\\ " + ver + "/SketchUp.app/" + "Contents/Info CFBundleVersion" ) );
	if(isnull( gsVer ) || ContainsString( gsVer, "does not exist" )){
		continue;
	}
	set_kb_item( name: "Google/SketchUp/MacOSX/Version", value: gsVer );
	cpe = build_cpe( value: gsVer, exp: "^([0-9.]+)", base: "cpe:/a:google:sketchup:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:google:sketchup";
	}
	path = "/Applications/Google SketchUp " + ver + "/SketchUp.app/";
	register_product( cpe: cpe, location: path );
	log_message( data: build_detection_report( app: "Google SketchUp", version: gsVer, install: path, cpe: cpe, concluded: gsVer ) );
}

