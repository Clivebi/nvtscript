if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802783" );
	script_version( "2019-08-14T14:30:23+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-08-14 14:30:23 +0000 (Wed, 14 Aug 2019)" );
	script_tag( name: "creation_date", value: "2012-05-16 10:35:58 +0530 (Wed, 16 May 2012)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Photoshop Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe Photoshop.

The script logs in via ssh, searches for folder 'Adobe Photoshop.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
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
for ver in make_list( "1",
	 "2",
	 "3",
	 "4",
	 "5",
	 "6" ) {
	photoVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ Photoshop\\ CS" + ver + "/Adobe\\ Photoshop\\ CS" + ver + ".app/Contents/Info CFBundleShortVersionString" ) );
	if(isnull( photoVer ) || ContainsString( photoVer, "does not exist" )){
		continue;
	}
	set_kb_item( name: "Adobe/Photoshop/MacOSX/Version", value: photoVer );
	cpe = build_cpe( value: photoVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:photoshop_cs" + ver + ":" );
	if(isnull( cpe )){
		cpe = "cpe:/a:adobe:photoshop_cs" + ver;
	}
	path = "/Applications/Adobe Photoshop CS" + ver;
	set_kb_item( name: "Adobe/Photoshop/MacOSX/Path", value: path );
	register_product( cpe: cpe, location: path );
	log_message( data: build_detection_report( app: "Adobe Photoshop", version: photoVer, install: path, cpe: cpe, concluded: photoVer ) );
}
if(isnull( photoVer ) || ContainsString( photoVer, "does not exist" )){
	for ver in make_list( "2014",
		 "2014.2.2",
		 "2015",
		 "2015.1",
		 "2015.5",
		 "2015.5.1",
		 "2017",
		 "2017.0.1",
		 "2017.1.0",
		 "2017.1.1",
		 "2018",
		 "2019" ) {
		photoVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "Adobe\\ Photoshop\\ CC\\ " + ver + "/Adobe\\ Photoshop\\ CC\\ " + ver + ".app/Contents/Info CFBundleShortVersionString" ) );
		if(isnull( photoVer ) || ContainsString( photoVer, "does not exist" )){
			continue;
		}
		set_kb_item( name: "Adobe/Photoshop/MacOSX/Version", value: photoVer );
		cpe = build_cpe( value: photoVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:photoshop_cc" + ver + ":" );
		if(isnull( cpe )){
			cpe = "cpe:/a:adobe:photoshop_cc" + ver;
		}
		path = "/Applications/Adobe Photoshop CC" + ver;
		set_kb_item( name: "Adobe/Photoshop/MacOSX/Path", value: path );
		register_product( cpe: cpe, location: path );
		log_message( data: build_detection_report( app: "Adobe Photoshop CC", version: ver + " " + photoVer, install: path, cpe: cpe, concluded: ver + " " + photoVer ) );
	}
}
close( sock );
exit( 0 );

