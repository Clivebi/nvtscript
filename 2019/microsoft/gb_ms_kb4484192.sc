if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815671" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-1464" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-04 14:14:00 +0000 (Mon, 04 May 2020)" );
	script_tag( name: "creation_date", value: "2019-12-11 07:35:22 +0530 (Wed, 11 Dec 2019)" );
	script_name( "Microsoft Office 2010 Service Pack 2 Information Disclosure Vulnerability (KB4484192)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484192" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to errors when Microsoft
  Excel improperly discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to obtain sensitive information and further compromise the user's system." );
	script_tag( name: "affected", value: "Microsoft Office 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484192" );
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
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer || !IsMatchRegexp( offVer, "^14\\." )){
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
	commonpath = registry_get_sz( key: key, item: "ProgramFilesDir" );
	if(!commonpath){
		continue;
	}
	offPath = commonpath + "\\Microsoft Office\\Office14";
	offexeVer = fetch_file_version( sysPath: offPath, file_name: "graph.exe" );
	if(offexeVer && version_in_range( version: offexeVer, test_version: "14.0", test_version2: "14.0.7243.4999" )){
		report = report_fixed_ver( file_checked: offPath + "\\graph.exe", file_version: offexeVer, vulnerable_range: "14.0 - 14.0.7243.4999" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

