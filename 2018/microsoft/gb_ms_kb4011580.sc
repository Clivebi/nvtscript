if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812618" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-0798", "CVE-2018-0801", "CVE-2018-0802", "CVE-2018-0812" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-10 11:52:29 +0530 (Wed, 10 Jan 2018)" );
	script_name( "Microsoft Office 2013 Service Pack 1 Remote Code Execution Vulnerabilities (KB4011580)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011580" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as Microsoft Office
  software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011580" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
commonpath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!commonpath){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^(15\\.)" )){
	offPath = commonpath + "\\Microsoft Shared\\EQUATION";
	msdllVer = fetch_file_version( sysPath: offPath, file_name: "eqnedt32.exe" );
	if( !msdllVer ){
		exit( 0 );
	}
	else {
		report = report_fixed_ver( file_checked: offPath + "\\eqnedt32.exe", file_version: msdllVer, vulnerable_range: "File 'eqnedt32.exe' present" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

