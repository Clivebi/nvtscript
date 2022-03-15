if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802787" );
	script_version( "$Revision: 13650 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-16 19:13:07 +0530 (Wed, 16 May 2012)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Illustrator Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe
Illustrator.

The script logs in via ssh, searches for folder 'Adobe Illustrator.app' and
queries the related 'info.plist' file for string 'CFBundleVersion' via command
line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
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
for ver in make_list( "",
	 "2",
	 "3",
	 "4",
	 "5",
	 "5.1",
	 "5.5",
	 "6" ) {
	illuVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ Illustrator\\ CS" + ver + "/Adobe\\ Illustrator.app/" + "Contents/Info CFBundleVersion" ) );
	if(isnull( illuVer ) || ContainsString( illuVer, "does not exist" )){
		continue;
	}
	install = TRUE;
	version = illuVer;
	app = "Adobe Illustrator CS";
	application = app + " " + ver;
}
if(!install){
	for ver in make_list( "",
		 "2014",
		 "2015",
		 "2017",
		 "2018" ) {
		illuVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ Illustrator\\ CC\\ " + ver + "/Adobe\\ Illustrator.app/" + "Contents/Info CFBundleVersion" ) );
		if(isnull( illuVer ) || ContainsString( illuVer, "does not exist" )){
			continue;
		}
		install = TRUE;
		version = illuVer;
		app = "Adobe Illustrator CC";
		application = app + " " + ver;
	}
}
close( sock );
if(install){
	set_kb_item( name: "Adobe/Illustrator/MacOSX/Version", value: version );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:adobe:illustrator:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:adobe:illustrator";
	}
	path = "/Applications/" + application + "/Adobe Illustrator.app";
	register_product( cpe: cpe, location: path );
	log_message( data: build_detection_report( app: application, version: version, install: path, cpe: cpe, concluded: version ) );
}
exit( 0 );

