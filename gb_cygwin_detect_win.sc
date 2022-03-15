if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806089" );
	script_version( "$Revision: 11015 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-13 17:30:01 +0530 (Tue, 13 Oct 2015)" );
	script_name( "Cygwin Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Cygwin on Windows.

  The script logs in via smb, searches for Cygwin in the registry and gets the
  version." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
key = "SOFTWARE\\Cygwin\\";
key1 = "SOFTWARE\\Wow6432Node\\Cygwin\\";
if(!registry_key_exists( key: key )){
	if(!registry_key_exists( key: key1 )){
		exit( 0 );
	}
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Cygwin\\setup" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Cygwin\\setup",
			 "SOFTWARE\\Wow6432Node\\Cygwin\\setup" );
	}
}
for key in key_list {
	cygPath = registry_get_sz( key: key, item: "rootdir" );
	if(!cygPath){
		cygPath = "Could not find the install location from registry";
	}
	if(ContainsString( cygPath, "cygwin" )){
		cygVer = "Unknown";
		set_kb_item( name: "Cygwin/Installed", value: TRUE );
		set_kb_item( name: "Cygwin/Win/Ver", value: cygVer );
		cpe = build_cpe( value: cygVer, exp: "^([0-9.]+)", base: "cpe:/a:redhat:cygwin:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:redhat:cygwin";
		}
		if(ContainsString( os_arch, "64" ) && ContainsString( cygPath, "64" )){
			set_kb_item( name: "Cygwin64/Win/Ver", value: cygVer );
			cpe = build_cpe( value: cygVer, exp: "^([0-9.]+)", base: "cpe:/a:redhat:cygwin:x64:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:redhat:cygwin:x64";
			}
		}
		register_product( cpe: cpe, location: cygPath );
		log_message( data: build_detection_report( app: "Cygwin", version: cygVer, install: cygPath, cpe: cpe, concluded: cygVer ) );
	}
}

