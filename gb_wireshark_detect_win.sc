if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800038" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Wireshark Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Wireshark on Windows.

The script logs in via smb, searches for Wireshark in the registry
and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
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
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
wireName = registry_get_sz( key: key + "Wireshark", item: "DisplayName" );
if(ContainsString( wireName, "Wireshark" )){
	wiresharkVer = registry_get_sz( key: key + "Wireshark", item: "DisplayVersion" );
	path = registry_get_sz( key: key + "Wireshark", item: "UninstallString" );
	if( path ){
		path = path - "\\uninstall.exe";
	}
	else {
		path = "Unable to find the install location from registry.";
	}
	if(wiresharkVer){
		set_kb_item( name: "Wireshark/Win/Ver", value: wiresharkVer );
		cpe = build_cpe( value: wiresharkVer, exp: "^([0-9.]+)", base: "cpe:/a:wireshark:wireshark:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:wireshark:wireshark";
		}
		if(ContainsString( os_arch, "64" ) && ContainsString( wireName, "64-bit" )){
			set_kb_item( name: "Wireshark64/Win/Ver", value: wiresharkVer );
			cpe = build_cpe( value: wiresharkVer, exp: "^([0-9.]+)", base: "cpe:/a:wireshark:wireshark:x64:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:wireshark:wireshark:x64";
			}
		}
		register_product( cpe: cpe, location: path );
		log_message( data: build_detection_report( app: wireName, version: wiresharkVer, install: path, cpe: cpe, concluded: wiresharkVer ) );
	}
}

