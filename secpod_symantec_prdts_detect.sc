if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900332" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Symantec Product(s) Detection (Windows SMB Login)" );
	script_tag( name: "summary", value: "SMB login-based detection of Symantec Product(s)." );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	key_list2 = make_list( "SOFTWARE\\Symantec\\Symantec Endpoint Protection\\SEPM" );
	sepm_key = "SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
		key_list2 = make_list( "SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\SEPM" );
		sepm_key = "SOFTWARE\\WOW6432Node\\Symantec\\Symantec Endpoint Protection\\CurrentVersion";
	}
}
if(!key_list){
	exit( 0 );
}
for symkey in key_list {
	for item in registry_enum_keys( key: symkey ) {
		symantecName = registry_get_sz( key: symkey + item, item: "DisplayName" );
		if(ContainsString( symantecName, "Norton AntiVirus" )){
			navVer = registry_get_sz( key: symkey + item, item: "DisplayVersion" );
			if(navVer){
				set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
				set_kb_item( name: "Symantec/Norton-AV/Ver", value: navVer );
				navPath = registry_get_sz( key: symkey + item, item: "InstallLocation" );
				if(!navPath){
					navPath = "Could not find the install Location from registry";
				}
				register_and_report_cpe( app: symantecName, ver: navVer, concluded: navVer, base: "cpe:/a:symantec:norton_antivirus:", expr: "^([0-9.]+)", insloc: navPath, regPort: 0, regService: "smb-login" );
			}
		}
		if(ContainsString( symantecName, "Norton Internet Security" )){
			nisVer = registry_get_sz( key: symkey + item, item: "DisplayVersion" );
			if(nisVer){
				set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
				set_kb_item( name: "Norton/InetSec/Ver", value: nisVer );
				nisPath = registry_get_sz( key: symkey + item, item: "InstallLocation" );
				if(!nisPath){
					nisPath = "Could not find the install Location from registry";
				}
				register_and_report_cpe( app: symantecName, ver: nisVer, concluded: nisVer, base: "cpe:/a:symantec:norton_internet_security:", expr: "^([0-9.]+)", insloc: nisPath, regPort: 0, regService: "smb-login" );
			}
		}
		if(ContainsString( symantecName, "Symantec pcAnywhere" )){
			pcawVer = registry_get_sz( key: symkey + item, item: "DisplayVersion" );
			if(pcawVer){
				set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
				set_kb_item( name: "Symantec/pcAnywhere/Ver", value: pcawVer );
				pcawPath = registry_get_sz( key: symkey + item, item: "InstallLocation" );
				if(!pcawPath){
					pcawPath = "Could not find the install Location from registry";
				}
				register_and_report_cpe( app: symantecName, ver: pcawVer, concluded: pcawVer, base: "cpe:/a:symantec:pcanywhere:", expr: "^([0-9.]+)", insloc: pcawPath, regPort: 0, regService: "smb-login" );
			}
		}
		if(ContainsString( symantecName, "Enterprise Security Manager" )){
			esmVer = registry_get_sz( key: symkey + item, item: "DisplayVersion" );
			if(esmVer){
				set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
				set_kb_item( name: "Symantec/ESM/Ver", value: esmVer );
				set_kb_item( name: "Symantec/ESM/Component", value: symantecName );
				esmPath = registry_get_sz( key: symkey + item, item: "InstallLocation" );
				if(!esmPath){
					esmPath = "Could not find the install Location from registry";
				}
				set_kb_item( name: "Symantec/ESM/Path", value: esmPath );
				register_and_report_cpe( app: symantecName, ver: esmVer, concluded: esmVer, base: "cpe:/a:symantec:enterprise_security_manager:", expr: "^([0-9.]+)", insloc: esmPath, regPort: 0, regService: "smb-login" );
			}
		}
		if(ContainsString( symantecName, "Symantec AntiVirus" )){
			savceVer = registry_get_sz( key: symkey + item, item: "DisplayVersion" );
			if(savceVer){
				set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
				set_kb_item( name: "Symantec/SAVCE/Ver", value: savceVer );
				savcePath = registry_get_sz( key: symkey + item, item: "InstallLocation" );
				if(!savcePath){
					savcePath = "Could not find the install Location from registry";
				}
				register_and_report_cpe( app: symantecName, ver: savceVer, concluded: savceVer, base: "cpe:/a:symantec:antivirus:", expr: "^([0-9.]+)", insloc: savcePath, regPort: 0, regService: "smb-login" );
			}
		}
		if(ContainsString( symantecName, "IMManager" )){
			imPath = registry_get_sz( key: symkey + item, item: "InstallSource" );
			if(imPath){
				imPath = imPath - "\\temp";
				imVer = fetch_file_version( sysPath: imPath, file_name: "IMLogicAdminService.exe" );
				if(imVer){
					set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
					set_kb_item( name: "Symantec/IM/Manager", value: imVer );
					register_and_report_cpe( app: symantecName, ver: imVer, concluded: imVer, base: "cpe:/a:symantec:im_manager:", expr: "^([0-9.]+)", insloc: imPath, regPort: 0, regService: "smb-login" );
				}
			}
		}
	}
}
for symkey in key_list2 {
	if(registry_key_exists( key: symkey )){
		nisVer = registry_get_sz( key: symkey, item: "Version" );
		if(nisVer){
			set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
			set_kb_item( name: "Symantec/Endpoint/Protection", value: nisVer );
			nisPath = registry_get_sz( key: symkey + item, item: "TargetDir" );
			if(nisPath){
				nisPath = "Could not find the install Location from registry";
			}
			nisType = registry_get_sz( key: symkey, item: "ProductType" );
			if( nisType && ContainsString( nisType, "sepsb" ) ){
				set_kb_item( name: "Symantec/SEP/SmallBusiness", value: nisType );
				base = "cpe:/a:symantec:endpoint_protection:" + nisVer + ":small_business";
			}
			else {
				base = "cpe:/a:symantec:endpoint_protection:";
			}
			register_and_report_cpe( app: "Symantec Endpoint Protection", ver: nisVer, concluded: nisVer, base: base, expr: "^([0-9.]+)", insloc: nisPath, regPort: 0, regService: "smb-login" );
		}
	}
}
if(registry_key_exists( key: sepm_key )){
	nisVer = registry_get_sz( key: sepm_key, item: "PRODUCTVERSION" );
	key = sepm_key + "\\Common Client";
	if(registry_key_exists( key: key )){
		sepm_path = registry_get_sz( key: key, item: "CCROOT" );
		if(sepm_path){
			nisPath = eregmatch( pattern: "(.*Symantec Endpoint Protection)", string: sepm_path );
			if(!isnull( nisPath[1] )){
				nisPath = nisPath[1];
			}
			if(!nisVer){
				version = eregmatch( pattern: "Symantec Endpoint Protection.*\\\\([0-9.]+)", string: sepm_path );
				if(!isnull( version[1] )){
					nisVer = version[1];
				}
			}
		}
	}
	if(nisVer){
		set_kb_item( name: "Symantec_or_Norton/Products/Win/Installed", value: TRUE );
		set_kb_item( name: "Symantec/Endpoint/Protection", value: nisVer );
		if(!nisPath){
			nisPath = "Could not find the install Location from registry";
		}
		register_and_report_cpe( app: "Symantec Endpoint Protection", ver: nisVer, concluded: nisVer, base: "cpe:/a:symantec:endpoint_protection:", expr: "^([0-9.]+)", insloc: nisPath, regPort: 0, regService: "smb-login" );
	}
}

