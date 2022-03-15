if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802778" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11015 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-15 12:12:47 +0530 (Tue, 15 May 2012)" );
	script_name( "Adobe Flash Professional Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe Flash Professional.

The script logs in via smb, searches for Adobe Flash Professional in the
registry and gets the version from 'Version' string in registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
appkey = "SOFTWARE\\Adobe\\Flash";
if(!registry_key_exists( key: appkey )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	flashName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(!egrep( pattern: "Adobe Flash CS([0-9.]+) Professional", string: flashName )){
		continue;
	}
	flashVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
	if(flashVer){
		ver = eregmatch( pattern: "CS([0-9.]+)", string: flashName );
		if(ver){
			version = ver[0] + " " + flashVer;
			set_kb_item( name: "Adobe/Flash/Prof/Win/Ver", value: version );
			cpe = build_cpe( value: flashVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:flash_cs" + ver[1] + ":" );
			path = "Could not find the install location from registry";
			if(!isnull( cpe )){
				register_product( cpe: cpe, location: path );
			}
			log_message( data: build_detection_report( app: "Adobe Flash Professional", version: version, install: path, cpe: cpe, concluded: version ) );
		}
	}
}

