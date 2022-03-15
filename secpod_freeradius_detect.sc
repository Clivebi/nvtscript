if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900855" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "FreeRADIUS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of FreeRADIUS." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "FreeRADIUS Version Detection";
radius_sock = ssh_login_or_reuse_connection();
if(!radius_sock){
	exit( 0 );
}
for name in make_list( "radiusd",
	 "freeradius" ) {
	radius_name = ssh_find_bin( prog_name: name, sock: radius_sock );
	for binName in radius_name {
		binName = chomp( binName );
		if(!binName){
			continue;
		}
		radius_ver = ssh_get_bin_version( full_prog_name: binName, sock: radius_sock, version_argv: "-v", ver_pattern: "FreeRADIUS Version ([0-9]\\.[0-9.]+)" );
		if(radius_ver[1] != NULL){
			set_kb_item( name: "FreeRADIUS/Ver", value: radius_ver[1] );
			log_message( data: "FreeRADIUS version " + radius_ver[1] + " running at location " + binName + " was detected on the host" );
			cpe = build_cpe( value: radius_ver[1], exp: "^([0-9.]+)", base: "cpe:/a:freeradius:freeradius:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}
ssh_close_connection();

