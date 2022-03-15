if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809282" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-09-22 16:43:00 +0530 (Thu, 22 Sep 2016)" );
	script_name( "HP Intelligent Management Center (iMC) Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  HP Intelligent Management Center (iMC).

  The script logs in via smb, searches for 'HP Intelligent Management Center' in the
  registry, gets version and installation path information from the registry." );
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
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		hpName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( hpName, "HP Intelligent Management Center" ) || ContainsString( hpName, "HPE Intelligent Management Center" )){
			hpPath = registry_get_sz( key: key + item, item: "UninstallString" );
			if(hpPath){
				hpPath = eregmatch( pattern: "(.*iMC)\\\\deploy\\\\jdk", string: hpPath );
				logPath = hpPath[1] + "\\deploy\\log\\deploylog.txt";
				install = hpPath[1];
				txtRead = smb_read_file( fullpath: logPath, offset: 0, count: 1000 );
				fileVer = eregmatch( pattern: "Version: iMC PLAT ([0-9.]+ \\([A-Za-z0-9]+)\\)", string: txtRead );
				hpVer = ereg_replace( pattern: "\\(", replace: "", string: fileVer[1] );
			}
			if(!hpVer){
				hpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
				hpPath = eregmatch( pattern: ".*.exe", string: hpPath );
				install = hpPath[0];
				if(!hpPath){
					hpPath = "Couldn find the install location from registry";
				}
			}
			if(hpVer){
				hpVer = ereg_replace( pattern: " ", string: hpVer, replace: "." );
				set_kb_item( name: "HPE/iMC/Win/Ver", value: hpVer );
				cpe = build_cpe( value: hpVer, exp: "([0-9A-Z. ]+)", base: "cpe:/a:hp:intelligent_management_center:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:hp:intelligent_management_center";
				}
				register_product( cpe: cpe, location: install );
				log_message( data: build_detection_report( app: "HP Intelligent Management Center", version: hpVer, install: install, cpe: cpe, concluded: hpVer ) );
				exit( 0 );
			}
		}
	}
}

