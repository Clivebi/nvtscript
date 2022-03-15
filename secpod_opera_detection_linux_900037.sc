if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900037" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Opera Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Opera.

  The script logs in via ssh, searches for executable 'opera' and
  greps the version executable found." );
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
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = NASLString( "Opera [0-9]\\\\+\\\\.[0-9]\\\\+" );
garg[5] = NASLString( "Internal\\\\ build\\\\ [0-9]\\\\+" );
garg[6] = NASLString( "Build\\\\ number:.*" );
checkdupOpera = "";
operaName = ssh_find_file( file_name: "/opera$", useregex: TRUE, sock: sock );
if(!operaName){
	ssh_close_connection();
	exit( 0 );
}
for binaryName in operaName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	operaVer = ssh_get_bin_version( full_prog_name: binaryName, version_argv: "-version", ver_pattern: "Opera ([0-9.]+) (Build ([0-9]+))?", sock: sock );
	if(operaVer && operaVer[1] && operaVer[3]){
		operaBuildVer = operaVer[1] + "." + operaVer[3];
	}
	if(operaVer && operaVer[1]){
		operaVer = operaVer[1];
	}
	if(!operaVer){
		arg1 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[3] + raw_string( 0x22 ) + " " + binaryName;
		arg2 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[5] + raw_string( 0x22 ) + " " + binaryName;
		arg3 = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[6] + raw_string( 0x22 ) + " " + binaryName;
		operaVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg1, ver_pattern: "Opera ([0-9]+\\.[0-9]+)", sock: sock );
		operaVer = operaVer[1];
	}
	if(operaVer){
		if(ContainsString( checkdupOpera, operaVer + ", " )){
			continue;
		}
		checkdupOpera += operaVer + ", ";
		set_kb_item( name: "Opera/Linux/Version", value: operaVer );
		register_and_report_cpe( app: "Opera", ver: operaVer, base: "cpe:/a:opera:opera:", expr: "([0-9.]+)", regPort: 0, insloc: binaryName, concluded: operaVer, regService: "ssh-login" );
		if(!operaBuildVer){
			operaBuildVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg2, ver_pattern: "Internal [B|b]uild ([0-9]+)", sock: sock );
			if(!operaBuildVer[1]){
				operaBuildVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg3, ver_pattern: "Build number:.*", sock: sock );
				operaBuildVer = operaBuildVer[1] - raw_string( 0x00 );
				operaBuildVer = eregmatch( pattern: "Build number:([0-9]+)", string: operaBuildVer );
				if(operaBuildVer && operaBuildVer[1]){
					operaBuildVer = operaVer + operaBuildVer[1];
				}
			}
		}
		if(!isnull( operaBuildVer )){
			buildVer = operaBuildVer;
			set_kb_item( name: "Opera/Build/Linux/Ver", value: buildVer );
		}
	}
}
ssh_close_connection();
exit( 0 );

