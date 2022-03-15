if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811163" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_cve_id( "CVE-2017-8476", "CVE-2017-8478", "CVE-2017-8479", "CVE-2017-8480", "CVE-2017-8481", "CVE-2017-8482", "CVE-2017-8485", "CVE-2017-8489", "CVE-2017-0299", "CVE-2017-8491", "CVE-2017-8492", "CVE-2017-0300", "CVE-2017-8462", "CVE-2017-8469" );
	script_bugtraq_id( 98903, 98845, 98856, 98857, 98862, 98858, 98860, 98865, 98884, 98869, 98870, 98901, 98900, 98842 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 13:53:00 +0000 (Tue, 19 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 09:35:26 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4022013)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4022013" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The Windows kernel improperly initializes objects in memory.

  - The Windows kernel fails to properly initialize a memory address, allowing
    an attacker to retrieve information that could lead to a Kernel Address Space
    Layout Randomization (KASLR) bypass." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022013" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "Advapi32.dll" );
if(!fileVer){
	exit( 0 );
}
if( version_is_less( version: fileVer, test_version: "6.0.6002.19598" ) ){
	Vulnerable_range = "Less than 6.0.6002.19598";
	VULN = TRUE;
}
else {
	if(version_in_range( version: fileVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.24107" )){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24107";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Advapi32.dll" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

