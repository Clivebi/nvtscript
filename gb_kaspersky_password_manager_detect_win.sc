if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812870" );
	script_version( "2020-02-28T07:55:18+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-28 07:55:18 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2018-05-02 16:59:41 +0530 (Wed, 02 May 2018)" );
	script_name( "Kaspersky Password Manager Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Kaspersky
  password manager. The script logs in via smb, searches for Kaspersky password
  manager in the registry and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_xref( name: "URL", value: "https://www.kaspersky.co.in/password-manager" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ) {
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(isnull( key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	kname = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( kname, "Kaspersky Password Manager" )){
		version = "unknown";
		kver = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(kver){
			version = kver;
		}
		kpath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!kpath){
			kpath = "Unable to find the install location from registry";
		}
		set_kb_item( name: "kaspersky/password_manager/detected", value: TRUE );
		cpe = build_cpe( value: kver, exp: "^([0-9.]+)", base: "cpe:/a:kaspersky:password_manager:" );
		if(!cpe){
			cpe = "cpe:/a:kaspersky:password_manager";
		}
		register_product( cpe: cpe, location: kpath, port: 0, service: "smb-login" );
		log_message( data: build_detection_report( app: "Kaspersky Password Manager", version: version, install: kpath, cpe: cpe, concluded: kver ) );
		exit( 0 );
	}
}
exit( 0 );

