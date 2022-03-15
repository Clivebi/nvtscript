if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815578" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-0850", "CVE-2020-0892" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-04 14:14:00 +0000 (Mon, 04 May 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 10:58:40 +0530 (Wed, 11 Mar 2020)" );
	script_name( "Microsoft Word Remote Code Execution Vulnerabilities (KB4484268)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484268." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "A flaw exists in Microsoft Word software
  when it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484268" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(version_in_range( version: exeVer, test_version: "16.0", test_version2: "16.0.4978.0999" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "16.0 - 16.0.4978.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

