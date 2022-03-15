if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811451" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-8570" );
	script_bugtraq_id( 99445 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-12 08:22:48 +0530 (Wed, 12 Jul 2017)" );
	script_name( "Microsoft Office 2013 Service Pack 1 Remote Code Execution Vulnerability (KB3213555)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3213555" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when it fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to use a specially crafted file to perform actions in the security context of
  the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3213555" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	offPath = commonpath + "\\Microsoft Shared\\Office15";
	offexeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
	if(offexeVer && version_in_range( version: offexeVer, test_version: "15.0", test_version2: "15.0.4945.1000" )){
		report = "File checked:     " + offPath + "\\Mso.dll" + "\n" + "File version:     " + offexeVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4945.1000" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

