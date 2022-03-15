if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815593" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-0906", "CVE-2020-0760" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-17 20:57:00 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-15 10:51:31 +0530 (Wed, 15 Apr 2020)" );
	script_name( "Microsoft Excel 2013 Remote Code Execution Vulnerabilities (KB4484283)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484283" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - A remote code execution vulnerability exists when Microsoft Office
    improperly loads arbitrary type libraries.

  - A remote code execution vulnerability exists in Microsoft Excel software
    when the software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Excel 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484283" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
if(!excelVer){
	exit( 0 );
}
excelPath = get_kb_item( "SMB/Office/Excel/Install/Path" );
if(!excelPath){
	excelPath = "Unable to fetch the install path";
}
if(version_in_range( version: excelVer, test_version: "15.0", test_version2: "15.0.5233.4999" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "15.0 - 15.0.5233.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

