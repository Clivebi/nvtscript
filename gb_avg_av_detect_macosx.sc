if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811311" );
	script_version( "2019-12-16T09:24:51+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-16 09:24:51 +0000 (Mon, 16 Dec 2019)" );
	script_tag( name: "creation_date", value: "2017-07-17 14:59:13 +0530 (Mon, 17 Jul 2017)" );
	script_name( "AVG AntiVirus Version Detection (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_tag( name: "summary", value: "Detects the installed version of
  AVG AntiVirus on MAC OS X.

  The script logs in via ssh, searches for folder 'AVGAntivirus.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion'
  via command line option 'defaults read'." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("cpe.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
name = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/AVGAntivirus.app/Contents/Info CFBundleName" ) );
if(ContainsString( name, "AVGAntiVirus" )){
	installVer = chomp( ssh_cmd( socket: sock, cmd: "defaults read /Applications/AVGAntivirus.app/Contents/Info CFBundleVersion" ) );
	if(!installVer || ContainsString( installVer, "does not exist" )){
		continue;
	}
	set_kb_item( name: "avg/antivirus/detected", value: TRUE );
	cpe = build_cpe( value: installVer, exp: "^([0-9.]+)", base: "cpe:/a:avg:anti-virus:" );
	if(!cpe){
		cpe = "cpe:/a:avg:anti-virus";
	}
	register_product( cpe: cpe, location: "/Applications", port: 0, service: "ssh-login" );
	log_message( data: build_detection_report( app: "AVG AntiVirus", version: installVer, install: "/Applications", cpe: cpe, concluded: installVer ), port: 0 );
}
ssh_close_connection();
exit( 0 );

