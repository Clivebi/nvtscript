if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804633" );
	script_version( "2021-02-15T14:13:17+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-15 14:13:17 +0000 (Mon, 15 Feb 2021)" );
	script_tag( name: "creation_date", value: "2014-06-09 16:03:10 +0530 (Mon, 09 Jun 2014)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Python Detection (SSH Login / Mac OS X)" );
	script_tag( name: "summary", value: "SSH login-based detection of Python for Mac OS X." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
pythonSeries = make_list( "2.5",
	 "2.6",
	 "2.7",
	 "3.0",
	 "3.1",
	 "3.2",
	 "3.3",
	 "3.4",
	 "3.5",
	 "3.6",
	 "3.7",
	 "3.8",
	 "3.9",
	 "3.10" );
found = FALSE;
for series in pythonSeries {
	cmd = "defaults read /Applications/Python\\ " + series + "/Python\\ Launcher.app/Contents/Info.plist CFBundleShortVersionString";
	version = chomp( ssh_cmd( socket: sock, cmd: cmd ) );
	if(!version || ContainsString( version, "does not exist" )){
		continue;
	}
	location = "/Applications/Python" + series + "/Python Launcher.app";
	set_kb_item( name: "python/ssh-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + cmd );
}
if(found){
	set_kb_item( name: "python/detected", value: TRUE );
	set_kb_item( name: "python/mac-os-x/detected", value: TRUE );
	set_kb_item( name: "python/ssh-login/detected", value: TRUE );
	set_kb_item( name: "python/ssh-login/port", value: port );
}
close( sock );
exit( 0 );

