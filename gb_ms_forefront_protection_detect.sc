if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804401" );
	script_version( "$Revision: 10915 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2014-02-12 09:36:29 +0530 (Wed, 12 Feb 2014)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Forefront Protection Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Forefront Protection.

The script logs in via smb, searches for Microsoft Forefront Protection
in the registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Microsoft Forefront" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	msfspName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(IsMatchRegexp( msfspName, "^Microsoft Forefront Server Protection$" )){
		msfspVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		msfspPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!msfspPath){
			msfspPath = "Could not find the install location from registry";
		}
		if(msfspVer){
			set_kb_item( name: "Microsoft/ForefrontServerProtection/Ver", value: msfspVer );
			cpe = build_cpe( value: msfspVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:microsoft_forefront_protection:" );
			if(!cpe){
				cpe = "cpe:/a:microsoft:microsoft_forefront_protection";
			}
			register_product( cpe: cpe, location: msfspPath );
			log_message( data: build_detection_report( app: msfspName, version: msfspVer, install: msfspPath, cpe: cpe, concluded: msfspVer ) );
		}
	}
}

