if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817171" );
	script_version( "2020-06-18T06:52:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-18 06:52:33 +0000 (Thu, 18 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 14:59:27 +0530 (Wed, 17 Jun 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Premiere Pro Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Premiere Pro.

  The script logs in via smb, searches for Adobe Premiere Pro in the
  registry and gets the version from 'DisplayVersion' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		adName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( adName, "Adobe Premiere Pro" )){
			adPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!adPath){
				adPath = "Couldn find the install location from registry";
			}
			adVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!adVer){
				adVer = "unknown";
			}
			set_kb_item( name: "adobe/premierepro/win/detected", value: TRUE );
			cpe = build_cpe( value: adVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:premiere_pro:" );
			if(!cpe){
				cpe = "cpe:/a:adobe:premiere_pro";
			}
			if(ContainsString( os_arch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
				set_kb_item( name: "adobe/premierepro/x64/win", value: TRUE );
				cpe = build_cpe( value: adVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:premiere_pro:x64:" );
				if(!cpe){
					cpe = "cpe:/a:adobe:premiere_pro:x64";
				}
			}
			register_and_report_cpe( app: "Adobe Premiere Pro", ver: adVer, concluded: "Adobe Premiere Pro", cpename: cpe, insloc: adPath );
			exit( 0 );
		}
	}
}
exit( 0 );

