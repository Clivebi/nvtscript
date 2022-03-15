if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108456" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-08 13:22:34 +0200 (Wed, 08 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "npm Packages Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.npmjs.com/" );
	script_tag( name: "summary", value: "SSH login-based detection of packages
  installated by the npm package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
func register_npms( buf, location ){
	var buf, location;
	set_kb_item( name: "ssh/login/npm_packages/locations", value: location );
	set_kb_item( name: "ssh/login/npm_packages" + location, value: buf );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
locations = ssh_find_file( file_name: "/node_modules$", useregex: TRUE, sock: sock );
for location in locations {
	location = chomp( location );
	if(!location || IsMatchRegexp( location, "^/usr/share" ) || IsMatchRegexp( location, "/node_modules/.+/node_modules" )){
		continue;
	}
	buf = ssh_cmd( socket: sock, cmd: "cd " + location + " && COLUMNS=400 npm list" );
	if(buf && IsMatchRegexp( buf, "^/.+" ) && !ContainsString( buf, "(empty)" )){
		register_npms( buf: buf, location: location );
		found = TRUE;
	}
}
buf = ssh_cmd( socket: sock, cmd: "COLUMNS=400 npm list -g" );
if(buf && IsMatchRegexp( buf, "^/.+" ) && !ContainsString( buf, "(empty)" )){
	register_npms( buf: buf, location: "/global" );
	found = TRUE;
}
if(found){
	set_kb_item( name: "ssh/login/npm_packages/detected", value: TRUE );
}
ssh_close_connection();
exit( 0 );

