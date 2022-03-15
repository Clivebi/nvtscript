if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817847" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-17128", "CVE-2020-17123", "CVE-2020-17125", "CVE-2020-17126", "CVE-2020-17130", "CVE-2020-17129" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 18:25:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-09 10:39:05 +0530 (Wed, 09 Dec 2020)" );
	script_name( "Microsoft Excel 2016 Security Feature Bypass And RCE Vulnerabilities (KB4486754)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4486754" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to microsoft excel
  software fails to properly handle specially crafted Office file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct remote code execution." );
	script_tag( name: "affected", value: "Microsoft Excel 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4486754" );
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
if(version_in_range( version: excelVer, test_version: "16.0", test_version2: "16.0.5095.0999" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "16.0 - 16.0.5095.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

