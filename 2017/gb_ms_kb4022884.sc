if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811150" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-8527", "CVE-2017-8528", "CVE-2017-0282", "CVE-2017-8531", "CVE-2017-0283", "CVE-2017-0284", "CVE-2017-8532", "CVE-2017-8533", "CVE-2017-0285", "CVE-2017-0287", "CVE-2017-8534", "CVE-2017-0288", "CVE-2017-0289" );
	script_bugtraq_id( 98933, 98949, 98885, 98819, 98920, 98918, 98820, 98821, 98914, 98922, 98822, 98923, 98929 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 20:15:00 +0000 (Tue, 19 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 08:23:45 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4022884)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4022884" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - When the Windows GDI component improperly discloses the contents of its memory.

  - When Windows Uniscribe improperly discloses the contents of its memory.

  - When the Windows font library improperly handles specially crafted
    embedded fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  could obtain information to further compromise the user's system. There are
  multiple ways an attacker could exploit the vulnerability, such as by convincing
  a user to open a specially crafted document, or by convincing a user to visit an
  untrusted webpage." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022884" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022884" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "Gdi32.dll" );
if(!fileVer){
	exit( 0 );
}
if( version_is_less( version: fileVer, test_version: "6.0.6002.19787" ) ){
	Vulnerable_range = "Less than 6.0.6002.19787";
	VULN = TRUE;
}
else {
	if(version_in_range( version: fileVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.24104" )){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24104";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Gdi32.dll" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );
