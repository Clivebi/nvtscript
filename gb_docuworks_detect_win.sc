if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811731" );
	script_version( "$Revision: 10888 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2017-09-08 14:22:17 +0530 (Fri, 08 Sep 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "DocuWorks Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  DocuWorks.

  The script logs in via smb, searches for 'Xerox DocuWorks' string and
  gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\FujiXerox" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(( ContainsString( appName, "Xerox DocuWorks" ) ) && ( !ContainsString( appName, "Viewer Light" ) )){
		appVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(appVer){
			insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insloc){
				insloc = "Could not find install location.";
			}
			set_kb_item( name: "DocuWorks/Win/Ver", value: appVer );
			cpe = build_cpe( value: appVer, exp: "([0-9.]+)", base: "cpe:/a:fujixerox:docuworks:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:fujixerox:docuworks";
			}
			if(ContainsString( os_arch, "x64" )){
				set_kb_item( name: "DocuWorksx64/Win/Ver", value: appVer );
				cpe = build_cpe( value: appVer, exp: "^([0-9.]+)", base: "cpe:/a:fujixerox:docuworks:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:fujixerox:docuworks:x64";
				}
			}
			register_product( cpe: cpe, location: insloc );
			log_message( data: build_detection_report( app: "DocuWorks", version: appVer, install: insloc, cpe: cpe, concluded: appVer ) );
			exit( 0 );
		}
	}
}
exit( 0 );

