if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808081" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-06-10 12:52:58 +0530 (Fri, 10 Jun 2016)" );
	script_name( "McAfee LiveSafe Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  McAfee LiveSafe.

  The script logs in via smb, searches for string 'McAfee' in the registry
  and reads the version information from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		livesafeName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( livesafeName, "McAfee LiveSafe" )){
			livesafeVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			livesafePath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!livesafePath){
				livesafePath = "Could not find the install location from registry";
			}
			if(livesafeVer){
				set_kb_item( name: "McAfee/LiveSafe/Win/Ver", value: livesafeVer );
				cpe = build_cpe( value: livesafeVer, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:livesafe:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:mcafee:livesafe";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "McAfee/LiveSafe64/Win/Ver", value: livesafeVer );
					cpe = build_cpe( value: livesafeVer, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:livesafe:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:mcafee:livesafe:x64";
					}
				}
				register_product( cpe: cpe, location: livesafePath );
				log_message( data: build_detection_report( app: livesafeName, version: livesafeVer, install: livesafePath, cpe: cpe, concluded: livesafeVer ) );
				exit( 0 );
			}
		}
	}
}

