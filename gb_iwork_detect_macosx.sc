if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802145" );
	script_version( "2020-03-02T13:53:38+0000" );
	script_tag( name: "last_modification", value: "2020-03-02 13:53:38 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "creation_date", value: "2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apple iWork Keynote Detection (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_family( "Product detection" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_tag( name: "summary", value: "This script finds the installed product version of Apple iWork Keynote." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
if(!get_kb_item( "ssh/login/osx_name" )){
	ssh_close_connection();
	exit( 0 );
}
for ver in make_list( "09",
	 "08",
	 "07",
	 "06",
	 "05" ) {
	path = "/Applications/iWork\\ \\'" + ver + "/Keynote.app";
	vers = chomp( ssh_cmd( socket: sock, cmd: "defaults read " + path + "/Contents/Info CFBundleShortVersionString" ) );
	if(!vers){
		continue;
	}
	if(!ContainsString( vers, "does not exist" )){
		break;
	}
}
close( sock );
if(!vers || ContainsString( vers, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "apple/iwork/keynote/detected", value: TRUE );
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:apple:keynote:" );
if(!cpe){
	cpe = "cpe:/a:apple:keynote";
}
register_product( cpe: cpe, location: path, port: 0, service: "ssh-login" );
log_message( data: build_detection_report( app: "Apple iWork Keynote", version: vers, install: path, cpe: cpe, concluded: vers ), port: 0 );
exit( 0 );

