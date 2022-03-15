if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812130" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11877", "CVE-2017-11878" );
	script_bugtraq_id( 101747, 101756 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-30 19:20:00 +0000 (Thu, 30 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-15 00:52:31 +0530 (Wed, 15 Nov 2017)" );
	script_name( "Microsoft Excel 2013 Service Pack 1 Multiple Vulnerabilities (KB4011233)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011233" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Microsoft Office software by not enforcing macro settings on
    an Excel document.

  - The software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass security and run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Excel 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011233" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
if(!excelVer){
	exit( 0 );
}
excelPath = get_kb_item( "SMB/Office/Excel/Install/Path" );
if(!excelPath){
	excelPath = "Unable to fetch the install path";
}
if(IsMatchRegexp( excelVer, "^15\\." ) && version_is_less( version: excelVer, test_version: "15.0.4981.1000" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "15.0 - 15.0.4981.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

