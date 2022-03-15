if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900921" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "TheGreenBow IPSec VPN Client Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of TheGreenBow IPSec VPN Client on Windows.

The script logs in via smb, searches for TheGreenBow IPSec VPN Client in the
registry, gets the from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		vpnName = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if(ContainsString( vpnName, "TheGreenBow VPN" )){
			path = registry_get_sz( key: key, item: "InstallLocation" );
			if(!path){
				path = vpnName - "vpnconf.exe";
			}
			vpnVer = fetch_file_version( sysPath: path, file_name: "vpnconf.exe" );
			if(!path){
				path = "Could not find the install location from registry";
			}
			if(vpnVer != NULL){
				set_kb_item( name: "TheGreenBow-IPSec-VPN-Client/Ver", value: vpnVer );
				cpe = build_cpe( value: vpnVer, exp: "^([0-9.]+)", base: "cpe:/a:thegreenbow:thegreenbow_vpn_client:" );
				if(!cpe){
					cpe = "cpe:/a:thegreenbow:thegreenbow_vpn_client";
				}
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "TheGreenBow-IPSec-VPN-Client64/Ver", value: vpnVer );
					cpe = build_cpe( value: vpnVer, exp: "^([0-9.]+)", base: "cpe:/a:thegreenbow:thegreenbow_vpn_client:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:thegreenbow:thegreenbow_vpn_client:x64";
					}
				}
				register_product( cpe: cpe, location: path );
				log_message( data: build_detection_report( app: "TheGreenBow VPN", version: vpnVer, install: path, cpe: cpe, concluded: vpnVer ) );
			}
		}
	}
}

