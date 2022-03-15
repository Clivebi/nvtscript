if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808069" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-06-07 11:23:59 +0530 (Tue, 07 Jun 2016)" );
	script_name( "Symantec Endpoint Encryption (SEE) Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Symantec Endpoint Encryption (SEE).

  The script logs in via smb, searches for 'Symantec Endpoint Encryption'
  in the registry and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
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
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	seeName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( seeName, "Symantec Endpoint Encryption" )){
		seeVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		seePath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!seePath){
			seePath = "Couldn find the install location from registry";
		}
		if(seeVer){
			set_kb_item( name: "Symantec/Endpoint/Encryption/Win/Ver", value: seeVer );
			cpe = build_cpe( value: seeVer, exp: "^([0-9.]+)", base: "cpe:/a:symantec:endpoint_encryption:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:symantec:endpoint_encryption";
			}
			if(ContainsString( os_arch, "64" )){
				set_kb_item( name: "Symantec/Endpoint/Encryption/Win64/Ver", value: seeVer );
				cpe = build_cpe( value: seeVer, exp: "^([0-9.]+)", base: "cpe:/a:symantec:endpoint_encryption:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:symantec:endpoint_encryption:x64";
				}
			}
			register_product( cpe: cpe, location: seePath );
			log_message( data: build_detection_report( app: seeName, version: seeVer, install: seePath, cpe: cpe, concluded: seeVer ) );
			exit( 0 );
		}
	}
}

