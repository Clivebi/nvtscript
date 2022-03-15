if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107341" );
	script_version( "2020-05-06T09:14:45+0000" );
	script_tag( name: "last_modification", value: "2020-05-06 09:14:45 +0000 (Wed, 06 May 2020)" );
	script_tag( name: "creation_date", value: "2018-09-20 17:07:53 +0200 (Thu, 20 Sep 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "EPiServer CMS Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version
  of EPiServer CMS." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("secpod_smb_func.inc.sc");
for key in nasl_make_list_unique( "CMS", registry_enum_keys( key: "SOFTWARE\\Wow6432Node\\EPiServer" ) ) {
	key = "SOFTWARE\\Wow6432Node\\EPiServer\\" + key;
	if(!registry_key_exists( key: key )){
		continue;
	}
	appName = registry_get_sz( key: key, item: "ProductName" );
	if(!IsMatchRegexp( appName, "EPiServer CMS" )){
		continue;
	}
	version = "unknown";
	for key2 in registry_enum_keys( key: key ) {
		loc = registry_get_sz( key: key + "\\" + key2, item: "InstallPath" );
		ver = registry_get_sz( key: key + "\\" + key2, item: "VersionName" );
		if(loc && ver && IsMatchRegexp( ver, "[0-9.]+" )){
			break;
		}
	}
	ver = eregmatch( string: ver, pattern: "^(Version )?([0-9.]+)" );
	if(ver[2]){
		version = ver[2];
	}
	set_kb_item( name: "EPiServer/EPiServer_CMS/Win/detected", value: TRUE );
	set_kb_item( name: "EPiServer/EPiServer_CMS/Win/Ver", value: version );
	register_and_report_cpe( app: "EPiServer CMS ", ver: version, concluded: ver[0], base: "cpe:/a:episerver:episerver:", expr: "^([0-9.]+)", insloc: loc );
	exit( 0 );
}
exit( 0 );

