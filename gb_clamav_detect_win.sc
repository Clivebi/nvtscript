if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800555" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ClamAV Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script retrieves ClamAV Version for Windows.

The script logs in via smb, searches for ClamWin or ClamAV or Immunet string in
the registry and gets the version from registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		clamName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( clamName, "ClamWin" ) || ContainsString( clamName, "ClamAV" )){
			clamVer = eregmatch( pattern: "ClamWin Free Antivirus ([0-9.]+)", string: clamName );
			clamPath = "Couldn find the install location from registry";
			if( clamVer[1] ){
				clamVer = clamVer[1];
			}
			else {
				clamVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			}
			if(clamVer){
				set_kb_item( name: "ClamAV/installed", value: TRUE );
				set_kb_item( name: "ClamAV/Win/Ver", value: clamVer );
				cpe = build_cpe( value: clamVer, exp: "^([0-9.]+)", base: "cpe:/a:clamav:clamav:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:clamav:clamav";
				}
			}
		}
	}
	if(!clamVer){
		key = key + "Immunet Protect\\";
		clamname = registry_get_sz( key: key, item: "DisplayName" );
		if(ContainsString( clamname, "ClamAV for Windows" ) || ContainsString( clamname, "Immunet" )){
			clamVer = registry_get_sz( key: key, item: "DisplayVersion" );
			clamPath = registry_get_sz( key: key, item: "UninstallString" );
			clamPath = clamPath - "uninstall.exe";
			if(clamVer){
				set_kb_item( name: "ClamAV/installed", value: TRUE );
				set_kb_item( name: "ClamAV/Win/Ver", value: clamVer );
				cpe = build_cpe( value: clamVer, exp: "^([0-9.]+)", base: "cpe:/a:clamav:clamav:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:clamav:clamav";
				}
			}
		}
	}
	if(clamVer){
		if(ContainsString( os_arch, "64" ) && !ContainsString( clamPath, "x86" )){
			set_kb_item( name: "ClamAV/installed", value: TRUE );
			set_kb_item( name: "ClamAV64/Win/Ver", value: clamVer );
			cpe = build_cpe( value: clamVer, exp: "^([0-9.]+)", base: "cpe:/a:clamav:clamav:x64:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:clamav:clamav:x64";
			}
		}
		register_product( cpe: cpe, location: clamPath );
		log_message( data: build_detection_report( app: "Clam Anti Virus", version: clamVer, install: clamPath, cpe: cpe, concluded: clamVer ) );
	}
}

