if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814540" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-8597", "CVE-2018-8598", "CVE-2018-8627", "CVE-2018-8636" );
	script_bugtraq_id( 106100, 106102, 106120, 106101 );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-12 15:50:46 +0530 (Wed, 12 Dec 2018)" );
	script_name( "Microsoft Excel 2013 Service Pack 1 Multiple Vulnerabilities (KB4461559)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4461559." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - In Microsoft Excel because it fails to properly handle objects in memory.

  - when Microsoft Excel improperly discloses the contents of its memory.

  - when Microsoft Excel software reads out of bound memory due to an
    uninitialized variable, which could disclose the contents of memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  run arbitrary code in the context of the current user, use the information to
  compromise the user's computer or data and view out of bound memory." );
	script_tag( name: "affected", value: "Microsoft Excel 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4461559" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( excelVer, "^15\\." ) && version_is_less( version: excelVer, test_version: "15.0.5093.1000" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "15.0 - 15.0.5093.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

