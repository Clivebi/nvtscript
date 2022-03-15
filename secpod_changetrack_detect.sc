if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900867" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Changetrack Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Changetrack." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Changetrack Version Detection";
change_sock = ssh_login_or_reuse_connection();
if(!change_sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/changetrack$", useregex: TRUE, sock: change_sock );
if(!paths){
	ssh_close_connection();
	exit( 0 );
}
for binName in paths {
	binName = chomp( binName );
	if(!binName){
		continue;
	}
	ctrack_ver = ssh_get_bin_version( full_prog_name: binName, version_argv: "-v", ver_pattern: "([0-9.]{3,})", sock: change_sock );
	if(!isnull( ctrack_ver[1] )){
		set_kb_item( name: "Changetrack/Ver", value: ctrack_ver[1] );
		log_message( data: "Changetrack version " + ctrack_ver[1] + " running at location " + binName + " was detected on the host" );
		cpe = build_cpe( value: ctrack_ver[1], exp: "^([0-9.]+)", base: "cpe:/a:cameron_morland:changetrack:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}
ssh_close_connection();

