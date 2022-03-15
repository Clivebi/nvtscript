if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801266" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Captivate Version Detection" );
	script_tag( name: "summary", value: "This script finds the installed Adobe Captivate version.

The script logs in via smb, searches for Adobe Captivate version in the
registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\AdobeCaptivate.exe" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\AdobeCaptivate.exe",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\AdobeCaptivate.exe" );
	}
}
if(!registry_key_exists( key: "SOFTWARE\\Adobe\\Adobe Captivate\\" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Adobe\\Adobe Captivate\\" )){
		exit( 0 );
	}
}
for key in key_list {
	capPath = registry_get_sz( key: key, item: "Path" );
	if(capPath){
		capVer = fetch_file_version( sysPath: capPath, file_name: "AdobeCaptivate.exe" );
		if(capVer){
			set_kb_item( name: "Adobe/Captivate/Ver", value: capVer );
			cpe = build_cpe( value: capVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:captivate:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:adobe:captivate";
			}
			if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) && !ContainsString( capPath, "x86" )){
				set_kb_item( name: "Adobe/Captivate64/Ver", value: capVer );
				cpe = build_cpe( value: capVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:captivate:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:adobe:captivate:x64";
				}
			}
			register_product( cpe: cpe, location: capPath );
			log_message( data: build_detection_report( app: "Adobe Captivate", version: capVer, install: capPath, cpe: cpe, concluded: capVer ) );
		}
	}
}

