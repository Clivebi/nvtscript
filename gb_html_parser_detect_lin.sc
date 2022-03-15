if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801038" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "HTML Parser Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of HTML Parser." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
parserSock = ssh_login_or_reuse_connection();
if(!parserSock){
	exit( 0 );
}
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = NASLString( "XS_VERSION.*" );
parserName = ssh_find_file( file_name: "/Parser\\.so$", useregex: TRUE, sock: parserSock );
if(!parserName){
	ssh_close_connection();
	exit( 0 );
}
for binaryName in parserName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[3] + raw_string( 0x22 ) + " " + binaryName;
	parserVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg, ver_pattern: "XS_VERSION.*", sock: parserSock );
	if(parserVer[1]){
		parserVer = chomp( parserVer[1] );
		parserVer = str_replace( find: raw_string( 0x00 ), replace: "", string: parserVer );
		if(ContainsString( parserVer, "HTML::Parser" ) || ContainsString( parserVer, "bootstrap parameter" )){
			parserVer = eregmatch( pattern: "([0-9.]+)", string: parserVer );
			if(parserVer[1]){
				set_kb_item( name: "HTML-Parser/Linux/Ver", value: parserVer[1] );
				register_and_report_cpe( app: "HTML-Parser", ver: parserVer[1], base: "cpe:/a:derrick_oswald:html-parser:", expr: "([0-9.]+)", regPort: 0, insloc: binaryName, concluded: parserVer[0], regService: "ssh-login" );
			}
		}
	}
}
ssh_close_connection();
exit( 0 );

