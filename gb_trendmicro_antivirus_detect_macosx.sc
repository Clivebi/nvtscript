if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814360" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-12-05 18:17:59 +0530 (Wed, 05 Dec 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Trend Micro Antivirus Version Detection (Mac OS X)" );
	script_tag( name: "summary", value: "Detects the installed version of Trend Micro
  Antivirus on Mac OS X.

  The script logs in via ssh, searches for folder 'PackageSelector.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'." );
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
appname = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "PackageSelector.app/Contents/Info CFBundleIdentifier" ) );
if(ContainsString( appname, "com.trendmicro.iTIS.PackageSelector" )){
	tmVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/" + "PackageSelector.app/Contents/Info CFBundleShortVersionString" ) );
}
close( sock );
if(isnull( tmVer ) || ContainsString( tmVer, "does not exist" )){
	exit( 0 );
}
set_kb_item( name: "TrendMicro/Antivirus/Macosx/Ver", value: tmVer );
cpe = build_cpe( value: tmVer, exp: "^([0-9.]+)", base: "cpe:/a:trend_micro:antivirus:" );
if(isnull( cpe )){
	cpe = "cpe:/a:trend_micro:antivirus";
}
register_product( cpe: cpe, location: "/Applications/PackageSelector.app", service: "ssh-login", port: 0 );
report = build_detection_report( app: "Trend Micro Antivirus", version: tmVer, install: "/Applications/PackageSelector.app", cpe: cpe, concluded: tmVer );
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

