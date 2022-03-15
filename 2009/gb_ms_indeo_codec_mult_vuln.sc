if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801090" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4210", "CVE-2009-4309", "CVE-2009-4310", "CVE-2009-4311", "CVE-2009-4312", "CVE-2009-4313" );
	script_bugtraq_id( 37251 );
	script_name( "Microsoft Windows Indeo Codec Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/976138" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/955759" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/954157.mspx" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/954157" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers compromise a vulnerable
  system." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the Indeo41 codec when processing a specific size within the
  'movi' record of a IV41 stream can be exploited to cause a heap-based buffer overflow.

  - An error in the Indeo41 codec when decompressing a video stream can be
  exploited to cause a stack-based buffer overflow.

  - An unspecified error in the Indeo codec can be exploited to corrupt memory.

  - An error in the Indeo32 codec when decoding a IV32 stream can be exploited
  to cause memory corruption.

  - Other vulnerabilities also exist and are caused due to unspecified errors
  in the Indeo codec and can be exploited to corrupt memory by tricking a user
  into viewing specially crafted media content." );
	script_tag( name: "summary", value: "This host is installed with Microsoft Windows Indeo codec and prone to
  multiple vulnerabilities." );
	script_tag( name: "solution", value: "The vendor has released updates, please see the references
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
func IndeoCodecVersion( filepath ){
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: filepath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: filepath );
	fileVer = GetVer( file: file, share: share );
	return fileVer;
}
if(hotfix_check_sp( xp: 4, win2003: 3, win2k: 5 ) <= 0){
	exit( 0 );
}
dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!dllPath){
	exit( 0 );
}
if(( hotfix_missing( name: "976138" ) == 1 )){
	if(hotfix_check_sp( win2k: 5 ) > 0){
		directxVer = registry_get_sz( key: "SOFTWARE\\Microsoft\\DirectX", item: "Version" );
		if(egrep( pattern: "^4\\.0[7-9]\\..*", string: directxVer )){
			quartzVer = IndeoCodecVersion( filepath: dllPath + "\\Quartz.dll" );
			if(quartzVer){
				if(version_is_less( version: quartzVer, test_version: "6.5.1.912" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
if(registry_key_exists( key: "SOFTWARE\\Classes\\CLSID\\{87CA6F02-49E4-11CF-A3FE" + "-00AA003735BE}\\InprocServer32" ) && registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32" )){
	axVer = IndeoCodecVersion( filepath: dllPath + "\\ir41_32.ax" );
	if(axVer){
		if(version_is_less_equal( version: axVer, test_version: "4.51.16.3" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
if(( hotfix_missing( name: "955759" ) == 1 )){
	aclayerPath = dllPath - "\\system32" - "\\System32" + "\\AppPatch\\Aclayers.dll";
	aclayerVer = IndeoCodecVersion( filepath: aclayerPath );
	if(aclayerVer){
		if( hotfix_check_sp( win2k: 5 ) > 0 ){
			if(version_is_less( version: aclayerVer, test_version: "5.0.2195.7358" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		else {
			if( hotfix_check_sp( xp: 4 ) > 0 ){
				SP = get_kb_item( "SMB/WinXP/ServicePack" );
				if( ContainsString( SP, "Service Pack 2" ) ){
					if(version_is_less( version: aclayerVer, test_version: "5.1.2600.3647" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				else {
					if(ContainsString( SP, "Service Pack 3" )){
						if(version_is_less( version: aclayerVer, test_version: "5.1.2600.5906" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			else {
				if(hotfix_check_sp( win2003: 3 ) > 0){
					SP = get_kb_item( "SMB/Win2003/ServicePack" );
					if(ContainsString( SP, "Service Pack 2" )){
						if(version_is_less( version: aclayerVer, test_version: "5.2.3790.4624" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

