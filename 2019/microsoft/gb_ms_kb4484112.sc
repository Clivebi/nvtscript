if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815635" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-1327", "CVE-2019-1331" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-10-09 11:10:35 +0530 (Wed, 09 Oct 2019)" );
	script_name( "Microsoft Excel 2016 Multiple Vulnerabilities (KB4484112)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4484112" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in Microsoft Excel because it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Excel 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4484112" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_in_range( version: excelVer, test_version: "16.0", test_version2: "16.0.4912.0999" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "16.0 - 16.0.4912.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

