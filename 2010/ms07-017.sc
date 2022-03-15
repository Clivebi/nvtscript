if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102055" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)" );
	script_bugtraq_id( 23273, 23276, 23278, 23275, 20940, 23277 );
	script_cve_id( "CVE-2006-5586", "CVE-2006-5758", "CVE-2007-1211", "CVE-2007-1212", "CVE-2007-1213", "CVE-2007-1215" );
	script_name( "Microsoft Windows GDI Multiple Vulnerabilities (925902)" );
	script_xref( name: "URL", value: "http://www.argeniss.com/research/ARGENISS-ADV-110604.txt" );
	script_xref( name: "URL", value: "http://projects.info-pull.com/mokb/MOKB-06-11-2006.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-017" );
	script_xref( name: "URL", value: "http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=499" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "Stack-based buffer overflow in the animated cursor code in Microsoft
  Windows 2000 SP4 through Vista allows remote attackers to execute
  arbitrary code or cause a denial of service (persistent reboot) via a
  large length value in the second (or later) anih block of a RIFF .ANI,
  cur, or .ico file, which results in memory corruption when processing
  cursors, animated cursors, and icons, a variant of CVE-2005-0416, as
  originally demonstrated using Internet Explorer 6 and 7." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, vista: 3 ) <= 0){
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(hotfix_missing( name: "925902" ) == 0){
	exit( 0 );
}
dllPath = registry_get_sz( item: "Install Path", key: "SOFTWARE\\Microsoft\\COM3\\Setup" );
dllPath += "\\gdi32.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath );
dllPath2 = registry_get_sz( item: "Install Path", key: "SOFTWARE\\Microsoft\\COM3\\Setup" );
dllPath2 += "\\user32.dll";
share2 = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath2 );
file2 = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath2 );
vers = GetVer( file: file, share: share );
vers2 = GetVer( file: file2, share: share2 );
if(!vers && !vers2){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 && vers ){
	SP = get_kb_item( "SMB/Win2K/ServicePack" );
	if(ContainsString( SP, "Service Pack 4" )){
		if(version_in_range( version: vers, test_version: "5.0", test_version2: "5.0.2195.7133" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 && vers ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: vers, test_version: "5.1", test_version2: "5.1.2600.3099" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
	else {
		if( hotfix_check_sp( win2003: 3 ) > 0 && vers ){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.3790.2892" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			else {
				if( ContainsString( SP, "Service Pack 2" ) ){
					if(version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.3790.4033" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
				else {
					if(ContainsString( SP, "Service Pack 0" )){
						if(version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.3790.651" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
							exit( 0 );
						}
					}
				}
			}
		}
		else {
			if(hotfix_check_sp( vista: 2 ) > 0 && vers2){
				SP = get_kb_item( "SMB/WinVista/ServicePack" );
				if(ContainsString( SP, "Service Pack 0" )){
					if(version_in_range( version: vers2, test_version: "6.0", test_version2: "6.0.6000.16438" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
			}
		}
	}
}
exit( 99 );

