if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813824" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-08-14 16:42:33 +0530 (Tue, 14 Aug 2018)" );
	script_name( "Nmap Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Nmap.

  The script logs in via smb, searches registry for Nmap and gets the version
  from 'DisplayVersion' string." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://nmap.org" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
for item in registry_enum_keys( key: key ) {
	nmapName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( nmapName, "Nmap" )){
		nmapVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(nmapVer){
			nmapPath = registry_get_sz( key: key + item, item: "UninstallString" );
			if(ContainsString( nmapPath, "\\uninstall.exe" )){
				nmapPath = nmapPath - "\\uninstall.exe";
			}
			if(!nmapPath){
				nmapPath = "Unable to find the install location from registry";
			}
			set_kb_item( name: "Nmap/Win/Ver", value: nmapVer );
			cpe = build_cpe( value: nmapVer, exp: "^([0-9.]+)", base: "cpe:/a:nmap:nmap:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:nmap:nmap";
			}
			register_product( cpe: cpe, location: nmapPath );
			log_message( data: build_detection_report( app: "Nmap", version: nmapVer, install: nmapPath, cpe: cpe, concluded: nmapVer ) );
			exit( 0 );
		}
	}
}

