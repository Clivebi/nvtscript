if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813388" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-06-05 11:48:39 +0530 (Tue, 05 Jun 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Horizon Client Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  VMware Horizon Client.

  The script logs in via ssh, searches for executable 'vmware-view' and queries
  the found executables via command line option '--version'" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
vm_sock = ssh_login_or_reuse_connection();
if(!vm_sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "vmware-view", sock: vm_sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	vmVer = ssh_get_bin_version( full_prog_name: bin, sock: vm_sock, version_argv: "--version", ver_pattern: "VMware Horizon Client ([0-9.]+)" );
	if(vmVer[1]){
		set_kb_item( name: "VMware/HorizonClient/Linux/Ver", value: vmVer[1] );
		cpe = build_cpe( value: vmVer[1], exp: "^([0-9.]+)", base: "cpe:/a:vmware:horizon_view_client:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:vmware:horizon_view_client";
		}
		register_product( cpe: cpe, location: bin );
		log_message( data: build_detection_report( app: "VMware Horizon Client", version: vmVer[1], install: bin, cpe: cpe, concluded: vmVer[1] ) );
		close( vm_sock );
		exit( 0 );
	}
}
close( vm_sock );
exit( 0 );

