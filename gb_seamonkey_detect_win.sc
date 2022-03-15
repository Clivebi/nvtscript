if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800016" );
	script_version( "2021-08-11T09:39:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-11 09:39:10 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)" );
	script_name( "Mozilla SeaMonkey Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of Mozilla SeaMonkey on Windows.

  The script logs in via smb, searches for Mozilla SeaMonkey in the registry
  and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key = "SOFTWARE";
}
else {
	if( ContainsString( os_arch, "x64" ) ) {
		key = "SOFTWARE\\Wow6432Node";
	}
	else {
		exit( 0 );
	}
}
seaVer = registry_get_sz( key: key + "\\mozilla.org\\SeaMonkey", item: "CurrentVersion" );
if(!seaVer){
	seaVer = registry_get_sz( key: key + "\\Mozilla\\SeaMonkey", item: "CurrentVersion" );
}
if(!seaVer){
	exit( 0 );
}
seaVer = eregmatch( pattern: "([0-9]+\\.[0-9.]+(\\s(RC\\s[0-9]+|Alpha|Beta))?)", string: seaVer );
seaVer = seaVer[1];
key = key + "\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "SeaMonkey" )){
		seaVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(seaVer){
			if(seaVer <= 0){
				continue;
			}
			insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insPath){
				insPath = "Could not find the install location";
			}
			set_kb_item( name: "Seamonkey/Win/Ver", value: seaVer );
			set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value: TRUE );
			baseCPE = "cpe:/a:mozilla:seamonkey:";
			cpeVer = str_replace( string: seaVer, find: " ", replace: "." );
			cpe = baseCPE + cpeVer;
			register_product( cpe: cpe, location: insPath, service: "smb-login", port: 0 );
			log_message( data: build_detection_report( app: appName, version: seaVer, install: insPath, cpe: cpe, concluded: seaVer ) );
		}
	}
}

