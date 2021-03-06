if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805168" );
	script_version( "$Revision: 10902 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-15 16:57:38 +0530 (Wed, 15 Apr 2015)" );
	script_name( "Microsoft Project Server Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Microsoft Project Server.

  The script logs in via smb, searches for Microsoft Project Server in the
  registry and gets the version from registry." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	if(psName = registry_get_sz( key: key + item, item: "DisplayName" )){
		if(ContainsString( psName, "Microsoft Project Server" )){
			psVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(psVer){
				insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insPath){
					insPath = "Could not find the install location from registry";
				}
				set_kb_item( name: "MS/ProjectServer/Server/Ver", value: psVer );
				cpe = build_cpe( value: psVer, exp: "^([0-9.]+[a-z0-9]*)", base: "cpe:/a:microsoft:project_server:" );
				if(!cpe){
					cpe = "cpe:/a:microsoft:project_server";
				}
				register_product( cpe: cpe, location: insPath );
				log_message( data: build_detection_report( app: psName, version: psVer, install: insPath, cpe: cpe, concluded: psVer ) );
			}
		}
	}
}

