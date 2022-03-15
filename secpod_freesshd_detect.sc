if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900959" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "freeSSHd Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of freeSSHd on Windows.

The script logs in via smb, searches for freeSSHd in the registry
and extract version from the name." );
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
	sshdName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( sshdName, "freeSSHd" )){
		sshdVer = eregmatch( pattern: "freeSSHd ([0-9.]+)", string: sshdName );
		if(!isnull( sshdVer[1] )){
			insLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insLoc){
				insLoc = "Could not find the install Location from registry";
			}
			set_kb_item( name: "freeSSHd/Ver", value: sshdVer[1] );
			cpe = build_cpe( value: sshdVer[1], exp: "^([0-9.]+)", base: "cpe:/a:freesshd:freesshd:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:freesshd:freesshd";
			}
			register_product( cpe: cpe, location: insLoc );
			log_message( data: build_detection_report( app: "freeSSHd", version: sshdVer[1], install: insLoc, cpe: cpe, concluded: sshdName ) );
		}
	}
}

