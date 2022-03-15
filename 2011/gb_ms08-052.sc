if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801725" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-01-18 10:00:48 +0100 (Tue, 18 Jan 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2007-5348", "CVE-2008-3012", "CVE-2008-3013", "CVE-2008-3014", "CVE-2008-3015" );
	script_bugtraq_id( 31018, 31019, 31020, 31021, 31022 );
	script_name( "Microsoft Products GDI Plus Remote Code Execution Vulnerabilities (954593)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-052" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_visual_prdts_detect.sc", "secpod_office_products_version_900032.sc", "smb_reg_service_pack.sc", "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to crash an affected application
  or execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2005 SP 2/3

  - Microsoft Office Excel Viewer 2007

  - Microsoft Office XP/2003 SP 3 and prior

  - Microsoft Office Visio 2002 SP 2 and prior

  - Microsoft Office Groove 2007 SP1 and prior

  - Microsoft Excel  Viewer 2003 SP 3 and prior

  - Microsoft Office 2007 System SP 1/2 and prior

  - Microsoft Office Word Viewer 2003 SP 3 and prior

  - Microsoft Office Visio Viewer 2007 SP 2 and prior

  - Microsoft Office PowerPoint Viewer 2007 SP 2 and prior

  - Microsoft Visual Studio 2008 SP 1 and prior

  - Microsoft Visual Studio .NET 2003 SP 1 and prior

  - Microsoft Windows 2000 SP4 with Internet Explorer 6 SP 1

  - Microsoft Office Compatibility Pack for Word/Excel/PowerPoint 2007 File Formats SP 1/2

  - Microsoft Office PowerPoint Viewer 2003

  - Microsoft Office PowerPoint Viewer 2007 Service Pack 1" );
	script_tag( name: "insight", value: "The issues are caused by memory corruptions, integer, heap and buffer
  overflows, and input validation errors in GDI+ when rendering malformed WMF,
  PNG, TIFF and BMP images, or when processing Office Art Property Tables in
  Office documents." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-052." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
func FileVer( file, path ){
	share = ereg_replace( pattern: "([A-Za-z]):.*", replace: "\\1$", string: path );
	if(IsMatchRegexp( share, "[a-z]\\$" )){
		share = toupper( share );
	}
	file = ereg_replace( pattern: "[A-Za-z]:(.*)", replace: "\\1", string: path + file );
	ver = GetVer( file: file, share: share );
	return ver;
}
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( item: "DisplayName", key: key + item );
	if(ContainsString( appName, "Visio" )){
		offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
		if(offPath){
			offPath += "\\Microsoft Shared\\OFFICE10";
			dllVer = FileVer( file: "\\Mso.dll", path: offPath );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "10.0", test_version2: "10.0.6843.9" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^10\\." )){
	offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(offPath){
		offPath += "\\Microsoft Shared\\OFFICE10";
		dllVer = FileVer( file: "\\Mso.dll", path: offPath );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "10.0", test_version2: "10.0.6844.9" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(offPath){
	offPath = offPath + "\\Microsoft Office\\OFFICE11";
	dllVer = FileVer( file: "\\Gdiplus.dll", path: offPath );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "11.0", test_version2: "11.0.8229.9" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
visioViewVer = get_kb_item( "SMB/Office/VisioViewer/Ver" );
grooveVer = get_kb_item( "SMB/Office/Groove/Version" );
xlViewVer = get_kb_item( "SMB/Office/XLView/Version" );
ppViewVer = get_kb_item( "SMB/Office/PPView/Version" );
cptPackVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(( officeVer && IsMatchRegexp( officeVer, "^12\\." ) ) || ( visioViewVer && IsMatchRegexp( visioViewVer, "^12\\." ) ) || ( grooveVer && IsMatchRegexp( grooveVer, "^12\\." ) ) || ( xlViewVer && IsMatchRegexp( xlViewVer, "^12\\." ) ) || ( ppViewVer && IsMatchRegexp( ppViewVer, "^12\\." ) ) || ( cptPackVer && IsMatchRegexp( cptPackVer, "^12\\." ) )){
	offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(offPath){
		offPath += "\\Microsoft Shared\\OFFICE12";
		dllVer = FileVer( file: "\\Ogl.dll", path: offPath );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6509.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
visStudNetVer = get_kb_item( "Microsoft/VisualStudio.Net/Ver" );
if(visStudNetVer && IsMatchRegexp( visStudNetVer, "^7\\." )){
	vsPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(vsPath){
		vsPath = vsPath + "\\Microsoft Shared\\Office10";
		vsVer = FileVer( file: "\\MSO.DLL", path: vsPath );
		if(vsVer){
			if(version_in_range( version: vsVer, test_version: "10.0", test_version2: "10.0.6843.9" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
visStudVer = get_kb_item( "Microsoft/VisualStudio/Ver" );
if(visStudVer && IsMatchRegexp( visStudVer, "^9\\." )){
	vsPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Microsoft SDKs\\Windows", item: "CurrentInstallFolder" );
	if(vsPath){
		vsPath = vsPath + "\\Bootstrapper\\Packages\\ReportViewer";
		rvVer = FileVer( file: "\\ReportViewer.exe", path: vsPath );
		if(rvVer){
			if(version_in_range( version: rvVer, test_version: "9.0", test_version2: "9.0.21022.142" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(hotfix_check_sp( win2k: 5 ) > 0){
	ieVer = get_kb_item( "MS/IE/EXE/Ver" );
	if(ieVer && IsMatchRegexp( ieVer, "^6\\.0\\.2800" )){
		dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
		if(dllPath){
			dllPath += "\\Microsoft Shared\\VGX";
			dllVer = FileVer( file: "\\vgx.dll", path: dllPath );
			if(dllVer){
				if(version_is_less( version: dllVer, test_version: "6.0.2800.1612" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\";
if(registry_key_exists( key: key )){
	for item in registry_enum_keys( key: key ) {
		sqlpath = registry_get_sz( key: key + item + "\\Setup", item: "SQLBinRoot" );
		sqlVer = FileVer( file: "\\sqlservr.exe", path: sqlpath );
		if(sqlVer){
			if(version_in_range( version: sqlVer, test_version: "2005.90.3000", test_version2: "2005.90.3072.9" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

