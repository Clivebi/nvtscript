if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900250" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)" );
	script_bugtraq_id( 43039 );
	script_cve_id( "CVE-2010-0818" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "MPEG-4 Codec Remote Code Execution Vulnerability (975558)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/975558" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code
  with elevated privileges on vulnerable systems." );
	script_tag( name: "insight", value: "The flaws exist in MPEG-4 codec included with Windows Media codecs, which
  does not properly handle specially crafted media files that use MPEG-4 video
  encoding." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-062." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior

  - Microsoft Windows Server 2008, when installed using the Server Core installation option is not affected by this vulnerability" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-062" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "975558" ) == 0){
	exit( 0 );
}
if(hotfix_check_sp( xp: 4 ) > 0 || hotfix_check_sp( win2003: 3 ) > 0){
	xpSP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(xpSP && !ContainsString( xpSP, "Service Pack 3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
	wmp11Installed = FALSE;
	wkey = "SOFTWARE\\Microsoft\\Active setup\\Installed Components\\";
	wmpVer = registry_get_sz( key: wkey + "{6BF52A52-394A-11d3-B153-00C04F79FAA6}", item: "Version" );
	if(IsMatchRegexp( wmpVer, "^(11,|11\\.)" )){
		wmp11Installed = TRUE;
	}
	sysPath = smb_get_system32root();
	if(!sysPath){
		exit( 0 );
	}
	affectedFiles = ["mpg4ds32.ax","mp4sds32.ax","mp4sdecd.dll"];
	for file in affectedFiles {
		if( file == "mp4sdecd.dll" && ( hotfix_check_sp( win2003: 3 ) > 0 ) ){
			continue;
		}
		else {
			if(file == "mp4sdecd.dll" && !wmp11Installed){
				continue;
			}
		}
		dllVer = fetch_file_version( sysPath: sysPath, file_name: file );
		if(!dllVer){
			continue;
		}
		if( file == "mpg4ds32.ax" ){
			checkVer = "8.0.0.4504";
		}
		else {
			if( file == "mp4sds32.ax" ){
				checkVer = "8.0.0.406";
			}
			else {
				if(file == "mp4sdecd.dll"){
					checkVer = "11.0.5721.5274";
				}
			}
		}
		if(version_is_less( version: dllVer, test_version: checkVer )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	exit( 0 );
}
if(hotfix_check_sp( winVista: 2 ) > 0 || hotfix_check_sp( win2008: 2 ) > 0){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(!SP){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
	}
	if( ContainsString( SP, "Service Pack 1" ) ){
		checkVer = "11.0.6001.7009";
	}
	else {
		if(ContainsString( SP, "Service Pack 2" )){
			checkVer = "11.0.6002.18236";
		}
	}
	sysPath = smb_get_system32root();
	if(!sysPath){
		exit( 0 );
	}
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Mp4sdecd.dll" );
	if(!dllVer){
		exit( 0 );
	}
	if(version_is_less( version: dllVer, test_version: checkVer )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

