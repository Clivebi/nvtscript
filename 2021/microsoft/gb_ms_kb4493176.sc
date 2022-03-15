if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817583" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-1713", "CVE-2021-1714" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 15:12:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-13 15:14:32 +0530 (Wed, 13 Jan 2021)" );
	script_name( "Microsoft Excel 2013 Remote Code Execution Vulnerabilities (KB4493176)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4493176" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple remote code execution vulnerabilities exist
  in Microsoft Excel software." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Excel 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4493176" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(version_in_range( version: excelVer, test_version: "15.0", test_version2: "15.0.5311.0999" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "15.0 - 15.0.5311.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

