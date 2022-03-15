if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902293" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-28 13:43:25 +0100 (Mon, 28 Feb 2011)" );
	script_name( "Metasploit Framework Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Metasploit Framework version.

  The script logs in via smb, searches for Metasploit in the registry and gets
  the version from 'DisplayVersion' string from the registry." );
	script_tag( name: "qod_type", value: "registry" );
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
		msName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( msName, "Metasploit" )){
			msVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(msVer){
				msPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!msPath){
					msPath = "Couldn find the install location from registry";
				}
				set_kb_item( name: "metasploit/framework/detected", value: TRUE );
				set_kb_item( name: "Metasploit/Framework/Win/Ver", value: msVer );
				cpe = build_cpe( value: msVer, exp: "^([0-9.]+)", base: "cpe:/a:metasploit:metasploit_framework:" );
				if(!cpe){
					cpe = "cpe:/a:metasploit:metasploit_framework";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "Metasploit/Framework64/Win/Ver", value: msVer );
					cpe = build_cpe( value: msVer, exp: "^([0-9.]+)", base: "cpe:/a:metasploit:metasploit_framework:x64:" );
					if(!cpe){
						cpe = "cpe:/a:metasploit:metasploit_framework:x64";
					}
				}
				register_product( cpe: cpe, location: msPath, port: 0, service: "smb-login" );
				log_message( data: build_detection_report( app: "Metasploit Framework", version: msVer, install: msPath, cpe: cpe, concluded: msVer ) );
			}
		}
	}
}

