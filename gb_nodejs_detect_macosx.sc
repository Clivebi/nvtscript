if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813474" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-07-10 11:02:12 +0530 (Tue, 10 Jul 2018)" );
	script_name( "Node.js Version Detection (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of
  Node.js on MAC OS X.

  The script logs in via ssh, and gets the version via command line option
  'node -v'." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "node", sock: sock );
for nodebin in paths {
	nodebin = chomp( nodebin );
	if(!nodebin){
		continue;
	}
	nodeVer = ssh_get_bin_version( full_prog_name: nodebin, sock: sock, version_argv: "-v", ver_pattern: "v([0-9.]+)" );
	if(nodeVer[1]){
		set_kb_item( name: "Nodejs/MacOSX/Installed", value: TRUE );
		set_kb_item( name: "Nodejs/MacOSX/Ver", value: nodeVer[1] );
		register_and_report_cpe( app: "Node.js", ver: nodeVer[1], base: "cpe:/a:nodejs:node.js:", expr: "^([0-9.]+)", insloc: nodebin );
		ssh_close_connection();
		exit( 0 );
	}
}
ssh_close_connection();
exit( 0 );

