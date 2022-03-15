if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107359" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2018-11-01 14:20:47 +0100 (Thu, 01 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sophos HitmanPro.Alert x86 Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Sophos HitmanPro.Alert." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
for key in nasl_make_list_unique( "HitmanPro.Alert", registry_enum_keys( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ) ) {
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + key;
	if(!registry_key_exists( key: key )){
		continue;
	}
	appName = registry_get_sz( key: key, item: "DisplayName" );
	if(!appName || !IsMatchRegexp( appName, "HitmanPro\\.Alert" )){
		continue;
	}
	loc = registry_get_sz( key: key, item: "InstallLocation" );
	ver = registry_get_sz( key: key, item: "DisplayVersion" );
	set_kb_item( name: "Sophos/HitmanPro.Alert/Win/detected", value: TRUE );
	set_kb_item( name: "Sophos/HitmanPro.Alert/Win/Ver", value: ver );
	register_and_report_cpe( app: "Sophos " + appName, ver: ver, base: "cpe:/a:sophos:hitmanpro.alert:", expr: "^([0-9.a-z-]+)", insloc: loc, regService: "smb-login", regPort: 0 );
	exit( 0 );
}
exit( 0 );

