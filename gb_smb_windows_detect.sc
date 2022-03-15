if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103621" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-12-11 10:59:09 +0200 (Tue, 11 Dec 2012)" );
	script_name( "Windows Version Detection (SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "SMB login-based detection of the installed Windows version." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("smb_nt.inc.sc");
SCRIPT_DESC = "Windows Version Detection (SMB Login)";
banner_type = "Registry access via SMB";
winVal = get_kb_item( "SMB/WindowsVersion" );
if(!winVal){
	exit( 0 );
}
winName = get_kb_item( "SMB/WindowsName" );
csdVer = get_kb_item( "SMB/CSDVersion" );
arch = get_kb_item( "SMB/Windows/Arch" );
build = get_kb_item( "SMB/WindowsBuild" );
if( isnull( csdVer ) ){
	csdVer = "";
}
else {
	csdVer = eregmatch( pattern: "Service Pack [0-9]+", string: csdVer );
	if(!isnull( csdVer[0] )){
		csdVer = csdVer[0];
	}
}
func register_win_version( cpe_base, win_vers, servpack, os_name, os_edition, os_branch, is64bit ){
	var cpe_base, win_vers, servpack, os_name, os_edition, os_branch, is64bit;
	var cpe;
	servpack = ereg_replace( string: servpack, pattern: "Service Pack ", replace: "sp", icase: TRUE );
	if( !isnull( servpack ) && strlen( servpack ) > 0 ){
		if(!win_vers){
			win_vers = "-";
		}
		cpe = cpe_base + ":" + win_vers + ":" + servpack;
		if( is64bit && os_edition ) {
			cpe += ":" + os_edition + "_x64";
		}
		else {
			if(is64bit){
				cpe += ":x64";
			}
		}
	}
	else {
		if( !isnull( win_vers ) && strlen( win_vers ) > 0 ){
			cpe = cpe_base + ":" + win_vers;
			if( os_edition && os_branch ){
				cpe += ":" + os_branch + ":" + os_edition;
				if(is64bit){
					cpe += "_x64";
				}
			}
			else {
				if( os_edition ){
					cpe += ":-:" + os_edition;
					if(is64bit){
						cpe += "_x64";
					}
				}
				else {
					if( os_branch ){
						cpe += ":" + os_branch;
						if(is64bit){
							cpe += ":x64";
						}
					}
					else {
						if(is64bit){
							cpe += ":-:x64";
						}
					}
				}
			}
		}
		else {
			cpe = cpe_base;
			if( os_edition && os_branch ){
				cpe += ":-:" + os_branch + ":" + os_edition;
				if(is64bit){
					cpe += "_x64";
				}
			}
			else {
				if( os_edition ){
					cpe += ":-:-:" + os_edition;
					if(is64bit){
						cpe += "_x64";
					}
				}
				else {
					if( os_branch ){
						cpe += ":-:" + os_branch;
						if(is64bit){
							cpe += ":x64";
						}
					}
					else {
						if(is64bit){
							cpe += ":-:-:x64";
						}
					}
				}
			}
		}
	}
	if(win_vers == "-"){
		win_vers = "";
	}
	os_register_and_report( os: os_name, version: win_vers, cpe: cpe, full_cpe: TRUE, banner_type: banner_type, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(winVal == "4.0"){
	register_win_version( cpe_base: "cpe:/o:microsoft:windows_nt", win_vers: "4.0", servpack: csdVer, os_name: winName );
}
if(winVal == "5.0" && ContainsString( winName, "Microsoft Windows 2000" )){
	register_win_version( cpe_base: "cpe:/o:microsoft:windows_2000", win_vers: "", servpack: csdVer, os_name: winName );
}
if(winVal == "5.1" && ContainsString( winName, "Microsoft Windows XP" )){
	register_win_version( cpe_base: "cpe:/o:microsoft:windows_xp", win_vers: "", servpack: csdVer, os_name: winName );
}
if(winVal == "5.2" && ContainsString( winName, "Microsoft Windows XP" ) && ContainsString( arch, "x64" )){
	register_win_version( cpe_base: "cpe:/o:microsoft:windows_xp", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
}
if(winVal == "5.2" && ContainsString( winName, "Microsoft Windows Server 2003" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2003", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2003", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.0" && ContainsString( winName, "Windows Vista" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_vista", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_vista", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.0" && ContainsString( winName, "Windows Server (R) 2008" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2008", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2008", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.1" && ContainsString( winName, "Windows 7" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_7", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_7", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.1" && ContainsString( winName, "Windows Server 2008 R2" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2008", win_vers: "r2", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2008", win_vers: "r2", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.2" && ContainsString( winName, "Windows Server 2012" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2012", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2012", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.2" && ContainsString( winName, "Windows 8" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_8", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_8", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.3" && ContainsString( winName, "Windows Server 2012 R2" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2012", win_vers: "r2", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2012", win_vers: "r2", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.3" && ContainsString( winName, "Windows 8.1" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_8.1", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_8.1", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if( winVal == "6.3" && ContainsString( winName, "Windows Embedded 8.1" ) ){
	register_win_version( cpe_base: "cpe:/o:microsoft:windows_embedded_8.1", win_vers: "", servpack: csdVer, os_name: winName );
}
else {
	if(( ContainsString( winName, "Windows Embedded" ) )){
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_embedded", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.3" && ContainsString( winName, "Windows 10" )){
	vers = "";
	os_branch = "";
	os_edition = "";
	if(ver = get_version_from_build( string: build, win_name: "win10" )){
		vers = tolower( ver );
	}
	if( ContainsString( winName, "LTSB" ) ) {
		os_branch = "ltsb";
	}
	else {
		if( ContainsString( winName, "LTSC" ) ) {
			os_branch = "ltsc";
		}
		else {
			os_branch = "cb";
		}
	}
	if( ContainsString( winName, "Enterprise" ) ) {
		os_edition = "enterprise";
	}
	else {
		if( ContainsString( winName, "Education" ) ) {
			os_edition = "education";
		}
		else {
			if( ContainsString( winName, "Home" ) ) {
				os_edition = "home";
			}
			else {
				if( ContainsString( winName, "Pro" ) ) {
					os_edition = "pro";
				}
				else {
					os_edition += "unknown_edition";
				}
			}
		}
	}
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_10", win_vers: vers, servpack: csdVer, os_name: winName, os_branch: os_branch, os_edition: os_edition, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_10", win_vers: vers, servpack: csdVer, os_name: winName, os_branch: os_branch, os_edition: os_edition );
	}
}
if(winVal == "6.3" && ContainsString( winName, "Windows Server 2016" )){
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2016", win_vers: "", servpack: csdVer, os_name: winName, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2016", win_vers: "", servpack: csdVer, os_name: winName );
	}
}
if(winVal == "6.3" && ContainsString( winName, "Windows Server 2019" )){
	vers = "";
	os_edition = "";
	if(ver = get_version_from_build( string: build, win_name: "win10" )){
		vers = tolower( ver );
	}
	if( ContainsString( winName, "Datacenter" ) ) {
		os_edition = "datacenter";
	}
	else {
		if( ContainsString( winName, "Standard" ) ) {
			os_edition = "standard";
		}
		else {
			os_edition += "unknown_edition";
		}
	}
	if( ContainsString( arch, "x64" ) ) {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2019", win_vers: vers, servpack: csdVer, os_name: winName, os_edition: os_edition, is64bit: TRUE );
	}
	else {
		register_win_version( cpe_base: "cpe:/o:microsoft:windows_server_2019", win_vers: vers, servpack: csdVer, os_name: winName, os_edition: os_edition );
	}
}
if(winVal && winName){
	os_register_unknown_banner( banner: "winVal = " + winVal + ", winName = " + winName + ", arch = " + arch, banner_type_name: banner_type, banner_type_short: "smb_win_banner" );
}
register_win_version( cpe_base: "cpe:/o:microsoft:windows", win_vers: "", servpack: csdVer, os_name: winName );
exit( 0 );

