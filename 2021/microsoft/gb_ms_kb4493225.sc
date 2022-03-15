if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817962" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-24108", "CVE-2021-27059" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-16 16:45:00 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 09:31:17 +0530 (Wed, 10 Mar 2021)" );
	script_name( "Microsoft Office 2016 Remote Code Execution Vulnerabilities (KB4493225)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4493225" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to microsoft office
  software fails to properly handle specially crafted Office file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4493225" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^16\\." )){
	os_arch = get_kb_item( "SMB/Windows/Arch" );
	if( ContainsString( os_arch, "x86" ) ){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
	}
	else {
		if(ContainsString( os_arch, "x64" )){
			key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
				 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
		}
	}
	for key in key_list {
		propath = registry_get_sz( key: key, item: "ProgramFilesDir" );
		if(propath){
			offPath = propath + "\\Microsoft Office\\root\\Office16";
			offexeVer = fetch_file_version( sysPath: offPath, file_name: "firstrun.exe" );
			if(!offexeVer){
				continue;
			}
			if(IsMatchRegexp( offexeVer, "^16\\." ) && version_is_less( version: offexeVer, test_version: "16.0.5095.1000" )){
				report = report_fixed_ver( file_checked: offPath + "\\firstrun.exe", file_version: offexeVer, vulnerable_range: "16.0 - 16.0.5095.0999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );
