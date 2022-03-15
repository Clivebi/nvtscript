if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807313" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-0135" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-04-13 09:03:18 +0530 (Wed, 13 Apr 2016)" );
	script_name( "Microsoft Windows Secondary Logon Privilege Elevation Vulnerability (3148538)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-046." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Windows Secondary
  Logon Service fails to properly manage request handles in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to run arbitrary code in kernel mode." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3148538" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-046" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Seclogon.dll" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( version_is_less( version: sysVer, test_version: "10.0.10240.16724" ) ){
		Vulnerable_range = "Less than 10.0.10240.16724";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: sysVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.161" )){
			Vulnerable_range = "10.0.10586.0 - 10.0.10586.161";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\System32\\Seclogon.dll" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

