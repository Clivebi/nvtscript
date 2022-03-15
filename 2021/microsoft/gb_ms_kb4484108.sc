if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818349" );
	script_version( "2021-09-29T08:01:30+0000" );
	script_cve_id( "CVE-2021-38650" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 08:01:30 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-27 17:47:00 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-15 07:51:35 +0530 (Wed, 15 Sep 2021)" );
	script_name( "Microsoft Office 2013 Service Pack 1 Spoofing Vulnerability (KB4484108)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484108" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when a maliciously
  modified file is opened in Microsoft Office." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484108" );
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
if(!officeVer || !IsMatchRegexp( officeVer, "^15\\." )){
	exit( 0 );
}
if(!os_arch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
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
		offPath = msPath + "\\Microsoft Office\\Office15";
		msdllVer = fetch_file_version( sysPath: offPath, file_name: "osf.dll" );
		if(msdllVer && IsMatchRegexp( msdllVer, "^15\\." )){
			if(version_is_less( version: msdllVer, test_version: "15.0.5381.1000" )){
				report = report_fixed_ver( file_checked: offPath + "\\osf.dll", file_version: msdllVer, vulnerable_range: "15.0 - 15.0.5381.0999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

