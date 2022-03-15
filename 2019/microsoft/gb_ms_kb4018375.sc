if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814987" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-1109" );
	script_bugtraq_id( 108965 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-19 16:07:00 +0000 (Fri, 19 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-10 11:03:43 +0530 (Wed, 10 Jul 2019)" );
	script_name( "Microsoft Office 2013 Spoofing Vulnerability (KB4018375)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4018375" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A spoofing vulnerability exists when
  Microsoft Office Javascript does not check the validity of the web page
  making a request to Office documents." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to conduct spoofing attacks and perform unauthorized actions,
  other attacks are also possible." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4018375/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(!officeVer || !IsMatchRegexp( officeVer, "^15\\." )){
	exit( 0 );
}
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
	msPath = registry_get_sz( key: key, item: "ProgramFilesDir" );
	if(msPath){
		exePath = msPath + "\\Microsoft Office\\Office15";
		exeVer = fetch_file_version( sysPath: exePath, file_name: "osf.dll" );
		if(!exeVer){
			continue;
		}
		if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.5153.0999" )){
			report = report_fixed_ver( file_checked: exePath + "\\osf.dll", file_version: exeVer, vulnerable_range: "15.0 - 15.0.5153.0999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

