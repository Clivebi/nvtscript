if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815554" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-0652" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-17 21:54:00 +0000 (Fri, 17 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-15 10:52:59 +0530 (Wed, 15 Jan 2020)" );
	script_name( "Microsoft Office 2010 Service Pack 2 Memory Corruption Vulnerability(KB4484236)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484236" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists when the software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484236" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
	if(offexeVer && version_in_range( version: offexeVer, test_version: "14.0", test_version2: "14.0.7244.4999" )){
		report = report_fixed_ver( file_checked: offPath + "\\graph.exe", file_version: offexeVer, vulnerable_range: "14.0 - 14.0.7244.4999" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

