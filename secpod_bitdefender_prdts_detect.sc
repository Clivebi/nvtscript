if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900326" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "BitDefender Product(s) Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of BitDefender Product(s) on Windows.

The script logs in via smb, searches for BitDefender Product(s) in the
registry and gets the version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
key = "SOFTWARE\\BitDefender";
if(!registry_key_exists( key: key )){
	key = "SOFTWARE\\Wow6432Node\\BitDefender";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\BitDefender\\About\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\BitDefender\\About\\",
			 "SOFTWARE\\Wow6432Node\\BitDefender\\About\\" );
	}
}
for bitKey in key_list {
	bitName = registry_get_sz( key: bitKey, item: "ProductName" );
	if(ContainsString( tolower( bitName ), "bitdefender internet security" )){
		bitVer = registry_get_sz( key: bitKey, item: "ProductVersion" );
		if(bitVer == NULL){
			if( ContainsString( bitKey, "Wow6432Node" ) ){
				key = "SOFTWARE\\Wow6432Node\\BitDefender\\BitDefender Desktop\\Maintenance\\InternetSecurity";
			}
			else {
				key = "SOFTWARE\\BitDefender\\BitDefender Desktop\\Maintenance\\InternetSecurity";
			}
			bitVer = registry_get_sz( key: key, item: "ProductVersion" );
		}
		if(bitVer){
			insLoc = registry_get_sz( key: bitKey - "About\\", item: "InstallDir" );
			if(!insLoc){
				insLoc = "Could not find the install Location from registry";
			}
			set_kb_item( name: "BitDefender/InetSec/Ver", value: bitVer );
			cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitdefender:internet_security:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:bitdefender:internet_security";
			}
			if(ContainsString( os_arch, "64" ) && !ContainsString( bitKey, "Wow6432Node" )){
				set_kb_item( name: "BitDefender64/InetSec/Ver", value: bitVer );
				cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitdefender:internet_security:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:bitdefender:internet_security:x64";
				}
			}
			register_product( cpe: cpe, location: insLoc );
			log_message( data: build_detection_report( app: bitName, version: bitVer, install: insLoc, cpe: cpe, concluded: bitVer ) );
		}
	}
	if(ContainsString( tolower( bitName ), "bitdefender antivirus" )){
		bitVer = registry_get_sz( key: bitKey, item: "ProductVersion" );
		if(bitVer == NULL){
			if( ContainsString( bitKey, "Wow6432Node" ) ){
				key = "SOFTWARE\\Wow6432Node\\BitDefender\\BitDefender Desktop\\Maintenance\\Antivirus";
			}
			else {
				key = "SOFTWARE\\BitDefender\\BitDefender Desktop\\Maintenance\\Antivirus";
			}
			bitVer = registry_get_sz( key: key, item: "ProductVersion" );
		}
		if(bitVer){
			insLoc = registry_get_sz( key: bitKey - "About\\", item: "InstallDir" );
			if(!insLoc){
				insLoc = "Could not find the install Location from registry";
			}
			set_kb_item( name: "BitDefender/AV/Ver", value: bitVer );
			cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitdefender:bitdefender_antivirus:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:bitdefender:bitdefender_antivirus";
			}
			if(ContainsString( os_arch, "64" ) && !ContainsString( bitKey, "Wow6432Node" )){
				set_kb_item( name: "BitDefender64/AV/Ver", value: bitVer );
				cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitdefender:bitdefender_antivirus:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:bitdefender:bitdefender_antivirus:x64";
				}
			}
			register_product( cpe: cpe, location: insLoc );
			log_message( data: build_detection_report( app: bitName, version: bitVer, install: insLoc, cpe: cpe, concluded: bitVer ) );
		}
	}
	if(ContainsString( tolower( bitName ), "bitdefender total security" )){
		bitVer = registry_get_sz( key: bitKey, item: "ProductVersion" );
		if(bitVer == NULL){
			if( ContainsString( bitKey, "Wow6432Node" ) ){
				key = "SOFTWARE\\Wow6432Node\\BitDefender\\BitDefender Desktop\\Maintenance\\TotalSecurity";
			}
			else {
				key = "SOFTWARE\\BitDefender\\BitDefender Desktop\\Maintenance\\TotalSecurity";
			}
			bitVer = registry_get_sz( key: key, item: "ProductVersion" );
		}
		if(bitVer){
			insLoc = registry_get_sz( key: bitKey - "About\\", item: "InstallDir" );
			if(!insLoc){
				insLoc = "Could not find the install Location from registry";
			}
			set_kb_item( name: "BitDefender/TotalSec/Ver", value: bitVer );
			cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitdefender:total_security:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:bitdefender:total_security";
			}
			if(ContainsString( os_arch, "64" ) && !ContainsString( bitKey, "Wow6432Node" )){
				set_kb_item( name: "BitDefender64/InetSec/Ver", value: bitVer );
				cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitdefender:total_security:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:bitdefender:total_security:x64";
				}
			}
			register_product( cpe: cpe, location: insLoc );
			log_message( data: build_detection_report( app: bitName, version: bitVer, install: insLoc, cpe: cpe, concluded: bitVer ) );
		}
	}
}

