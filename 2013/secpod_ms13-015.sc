if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902950" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 57847 );
	script_cve_id( "CVE-2013-0073" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-02-13 13:21:23 +0530 (Wed, 13 Feb 2013)" );
	script_name( "Microsoft .NET Framework Privilege Elevation Vulnerability (2800277)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2800277" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-015" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4

  - Microsoft .NET Framework 4.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 2.0 Service Pack 2" );
	script_tag( name: "insight", value: "The flaw is due to an error when handling permissions of a callback function
  when a certain WinForm object is created and can be exploited to bypass CAS
  (Code Access Security) restrictions via a specially crafted XAML Browser
  Application (XBAP) or an untrusted .NET application." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-015." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(ContainsString( path, "\\Microsoft.NET\\Framework" )){
		if(ContainsString( path, "v4.0.30319" )){
			dllv4 = fetch_file_version( sysPath: path, file_name: "system.windows.forms.dll" );
		}
		if(ContainsString( path, "v2.0.50727" )){
			dllv2 = fetch_file_version( sysPath: path, file_name: "system.windows.forms.dll" );
		}
	}
}
if(dllv4 && ( version_in_range( version: dllv4, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1001" ) || version_in_range( version: dllv4, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2002" ) )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
if(dllv2 && ( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 )){
	if(version_in_range( version: dllv2, test_version: "2.0.50727.0000", test_version2: "2.0.50727.4985" ) || version_in_range( version: dllv2, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7014" ) || version_in_range( version: dllv2, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5467" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(dllv2 && ( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 )){
	if(version_in_range( version: dllv2, test_version: "2.0.50727.0000", test_version2: "2.0.50727.4235" ) || version_in_range( version: dllv2, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7014" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(dllv2 && ( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 )){
	if(version_in_range( version: dllv2, test_version: "2.0.50727.0000", test_version2: "2.0.50727.3644" ) || version_in_range( version: dllv2, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7014" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(dllv4 && ( hotfix_check_sp( win7: 2, win2008: 3, win7x64: 2, win2008r2: 2, winVista: 3 ) > 0 )){
	if(version_in_range( version: dllv4, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18035" ) || version_in_range( version: dllv4, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19051" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

