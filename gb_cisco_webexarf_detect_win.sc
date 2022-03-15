if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107078" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-10 11:19:11 +0100 (Thu, 10 Nov 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Cisco WebEx ARF (Advanced Recording Format) Player Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Cisco WebEx Advanced Recording Format (ARF) Player.

  The script logs in via smb, searches for Cisco WebEx Advanced Recording Format (ARF) Player in the registry and gets the version from 'DisplayVersion' string from registry." );
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
		wpName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( wpName, "Network Recording Player" )){
			wpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			wpPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!wpPath){
				wpPath = "Unable to find the install location from registry";
			}
			if(wpVer){
				set_kb_item( name: "Cisco/Arfplayer/Win/Ver", value: wpVer );
				cpe = build_cpe( value: wpVer, exp: "^([0-9.]+)", base: "cpe:/a:cisco:webex_arf_player:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:cisco:webex_arf_player";
				}
				if(ContainsString( os_arch, "x64" ) && !ContainsString( wpPath, "x86" )){
					set_kb_item( name: "Cisco/Arfplayer64/Win/Ver", value: wpVer );
					cpe = build_cpe( value: wpVer, exp: "^([0-9.]+)", base: "cpe:/a:cisco:webex_arf_player:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:cisco:webex_arf_player:x64";
					}
				}
				register_product( cpe: cpe, location: wpPath );
				log_message( data: build_detection_report( app: "Cisco Webex ARF Player", version: wpVer, install: wpPath, cpe: cpe, concluded: wpVer ) );
			}
		}
	}
}
exit( 0 );

