if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803368" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2013-04-04 17:10:57 +0530 (Thu, 04 Apr 2013)" );
	script_name( "Ovaldi Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Ovaldi.

  The script logs in via ssh, searches for executable 'ovaldi' and
  queries the found executables via command line option '-V'." );
	exit( 0 );
}
require("cpe.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
path = ssh_find_bin( prog_name: "ovaldi", sock: sock );
for binName in path {
	binName = chomp( binName );
	if(!binName){
		continue;
	}
	ovaldiVer = ssh_get_bin_version( full_prog_name: binName, version_argv: "-V", ver_pattern: "Version: ([0-9.]+).?(Build: ([0-9]+))?", sock: sock );
	if( !isnull( ovaldiVer[1] ) && !isnull( ovaldiVer[3] ) ){
		ver = ovaldiVer[1] + "." + ovaldiVer[3];
	}
	else {
		if(!isnull( ovaldiVer[1] ) && isnull( ovaldiVer[3] )){
			ver = ovaldiVer[1];
		}
	}
	if(ver){
		set_kb_item( name: "Ovaldi/Linux/Version", value: ver );
		cpe = build_cpe( value: ver, exp: "^([0-9.]+)", base: "cpe:/a:mitre:ovaldi:" );
		if(!cpe){
			cpe = "cpe:/a:mitre:ovaldi";
		}
		register_product( cpe: cpe, location: binName, service: "ssh-login" );
		log_message( data: build_detection_report( app: "Ovaldi", version: ver, install: binName, cpe: cpe, concluded: ovaldiVer[0] ) );
	}
}
ssh_close_connection();
exit( 0 );

