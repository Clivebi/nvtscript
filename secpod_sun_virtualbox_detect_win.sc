if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901053" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)" );
	script_name( "Sun VirtualBox Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Sun/Oracle VirtualBox.

  The script logs in via smb, searches for Sun/Oracle VirtualBox in the registry
  and gets the version from 'Version' string in registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
func building_cpe( version, insPath ){
	set_kb_item( name: "Oracle/VirtualBox/Win/Ver", value: version );
	set_kb_item( name: "VirtualBox/Win/installed", value: TRUE );
	if( version_is_less( version: version, test_version: "3.2.0" ) ){
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sun:virtualbox:" );
		if(!( cpe )){
			cpe = "cpe:/a:sun:virtualbox";
		}
		if(cpe){
			register_product( cpe: cpe, location: insPath );
		}
		log_message( data: build_detection_report( app: "Sun/Oracle VirtualBox", version: version, install: insPath, cpe: cpe, concluded: version ) );
	}
	else {
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:oracle:vm_virtualbox:" );
		if(!( cpe )){
			cpe = "cpe:/a:oracle:vm_virtualbox";
		}
		if(cpe){
			register_product( cpe: cpe, location: insPath );
		}
		log_message( data: build_detection_report( app: "Sun/Oracle VirtualBox", version: version, install: insPath, cpe: cpe, concluded: version ) );
	}
}
checkdupvmVer = "";
if(!registry_key_exists( key: "SOFTWARE\\Sun\\VirtualBox" ) && !registry_key_exists( key: "SOFTWARE\\Sun\\xVM VirtualBox" ) && !registry_key_exists( key: "SOFTWARE\\Oracle\\VirtualBox" )){
	exit( 0 );
}
vmVer = registry_get_sz( key: "SOFTWARE\\Oracle\\VirtualBox", item: "version" );
if(vmVer && egrep( string: vmVer, pattern: "^([0-9.]+)" )){
	if(ContainsString( checkdupvmVer, vmVer + ", " )){
		continue;
	}
	checkdupvmVer += vmVer + ", ";
	inPath = registry_get_sz( key: "SOFTWARE\\Oracle\\VirtualBox", item: "InstallDir" );
	if(!inPath){
		inPath = "Could not find the install location from registry";
	}
	building_cpe( version: vmVer, insPath: inPath );
}
path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for item in registry_enum_keys( key: path ) {
	vbname = registry_get_sz( key: path + item, item: "DisplayName" );
	if( ContainsString( vbname, "Sun VirtualBox" ) || ContainsString( vbname, "Oracle VM VirtualBox" ) ){
		vmVer = registry_get_sz( key: path + item, item: "DisplayVersion" );
		if(vmVer && egrep( string: vmVer, pattern: "^([0-9.]+)" )){
			if(ContainsString( checkdupvmVer, vmVer + ", " )){
				continue;
			}
			checkdupvmVer += vmVer + ", ";
			inPath = registry_get_sz( key: path + item, item: "InstallLocation" );
			if(!inPath){
				inPath = "Could not find the install Location from registry";
			}
			building_cpe( version: vmVer, insPath: inPath );
		}
	}
	else {
		if(ContainsString( vbname, "Sun xVM VirtualBox" ) || ContainsString( vbname, "Oracle xVM VirtualBox" )){
			xvmVer = registry_get_sz( key: path + item, item: "DisplayVersion" );
			if(xvmVer && egrep( string: xvmVer, pattern: "^([0-9.]+)" )){
				set_kb_item( name: "Sun/xVM-VirtualBox/Win/Ver", value: xvmVer );
				set_kb_item( name: "VirtualBox/Win/installed", value: TRUE );
				inPath = registry_get_sz( key: path + item, item: "InstallLocation" );
				if(!inPath){
					inPath = "Could not find the install location from registry";
				}
				cpe = build_cpe( value: xvmVer, exp: "^([0-9.]+)", base: "cpe:/a:sun:xvm_virtualbox:" );
				if(!( cpe )){
					cpe = "cpe:/a:sun:xvm_virtualbox:";
				}
				if(cpe){
					register_product( cpe: cpe, location: inPath );
				}
				log_message( data: build_detection_report( app: "Sun/Oracle xVirtualBox ", version: xvmVer, install: inPath, cpe: cpe, concluded: xvmVer ) );
			}
		}
	}
}

