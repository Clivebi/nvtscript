if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807338" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-3205", "CVE-2016-3206", "CVE-2016-3207" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-06-15 08:55:39 +0530 (Wed, 15 Jun 2016)" );
	script_name( "Microsoft Windows JScript and VBScript Remote Code Execution Vulnerabilities (3163640)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-069." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple remote code execution flaws exist
  in the way that the JScript 9, JScript, and VBScript engines render when
  handling objects in memory in Internet Explorer." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently
  logged-in user." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3163640" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-069" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Vbscript.dll" );
if(!dllVer){
	exit( 0 );
}
if( IsMatchRegexp( dllVer, "^(5\\.7\\.6002\\.2)" ) ){
	Vulnerable_range = "5.7.6002.23000 - 5.7.6002.23966";
}
else {
	if(IsMatchRegexp( dllVer, "^(5\\.7\\.6002\\.1)" )){
		Vulnerable_range = "Less than 5.7.6002.19652";
	}
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(version_is_less( version: dllVer, test_version: "5.7.6002.19652" ) || version_in_range( version: dllVer, test_version: "5.7.6002.23000", test_version2: "5.7.6002.23966" )){
		report = "File checked:     " + sysPath + "\\system32\\Vbscript.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

