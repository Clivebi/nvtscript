if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801115" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Shibboleth Service Provider Version Detection" );
	script_tag( name: "summary", value: "This script detects the installed version of
  Shibboleth Service Provider." );
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
if(!registry_key_exists( key: "SOFTWARE\\Shibboleth" )){
	exit( 0 );
}
shibloc = registry_get_sz( key: "SOFTWARE\\Shibboleth", item: "InstallDir" );
if(!shibloc){
	shibloc = "Couldn find the install location from registry";
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	shibName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( shibName, "Shibboleth" )){
		shibVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(shibVer){
			set_kb_item( name: "Shibboleth/SP/Win/Ver", value: shibVer );
			cpe = build_cpe( value: shibVer, exp: "^([0-9.]+)", base: "cpe:/a:internet2:shibboleth-sp:" );
			if(!cpe){
				cpe = "cpe:/a:internet2:shibboleth-sp";
			}
			register_and_report_cpe( app: "Shibboleth SP", ver: shibVer, concluded: shibVer, cpename: cpe, insloc: shibloc );
			exit( 0 );
		}
	}
}
exit( 0 );

