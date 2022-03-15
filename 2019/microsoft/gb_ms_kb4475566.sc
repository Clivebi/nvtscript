if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815281" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-1263", "CVE-2019-1297" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "creation_date", value: "2019-09-11 09:04:51 +0530 (Wed, 11 Sep 2019)" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Microsoft Excel 2013 Service Pack 1 Multiple Vulnerabilities (KB4475566)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4475566" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist in Microsoft Excel due to:

  - improper disclosure of memory contents.

  - improper handling of objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  run arbitrary code in the context of the current user or use the disclosed information
  to compromise the users computer or data." );
	script_tag( name: "affected", value: "Microsoft Excel 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4475566" );
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
if(IsMatchRegexp( excelVer, "^15\\." ) && version_is_less( version: excelVer, test_version: "15.0.5172.1000" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "15.0 - 15.0.5172.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

