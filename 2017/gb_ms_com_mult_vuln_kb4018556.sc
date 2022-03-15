if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811118" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2017-0213", "CVE-2017-0214", "CVE-2017-0244", "CVE-2017-0258" );
	script_bugtraq_id( 98112, 98109, 98103, 98102 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2017-05-10 12:51:18 +0530 (Wed, 10 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft COM Multiple Vulnerabilities (KB4018556)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4018556" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The Windows kernel improperly initializes objects in memory.

  - The way that the Windows Kernel handles objects in memory.

  - Windows fails to properly validate input before loading type libraries.

  - An unspecified error in Windows COM Aggregate Marshaler." );
	script_tag( name: "impact", value: "An attacker who successfully exploited the
  vulnerability can elevate their privilege level, can lead to denial of
  service condition, could obtain information to further compromise the users
  system and run arbitrary code with elevated privileges." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-gb/help/4018556" );
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
if(!asVer = fetch_file_version( sysPath: sysPath, file_name: "Ole32.dll" )){
	exit( 0 );
}
if( version_is_less( version: asVer, test_version: "6.0.6002.19773" ) ){
	Vulnerable_range = "Less than 6.0.6002.19773";
	VULN = TRUE;
}
else {
	if(version_in_range( version: asVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.24088" )){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24088";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Ole32.dll" + "\n" + "File version:     " + asVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

