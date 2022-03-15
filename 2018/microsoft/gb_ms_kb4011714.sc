if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812977" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_cve_id( "CVE-2018-0907" );
	script_bugtraq_id( 103325 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-03-14 08:54:01 +0530 (Wed, 14 Mar 2018)" );
	script_name( "Microsoft Excel 2007 Service Pack 3 Security Feature Bypass Vulnerability (KB4011714)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011714" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in Microsoft
  Office software which do not enforce macro settings on an Excel document." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to bypass security feature and conduct further attacks." );
	script_tag( name: "affected", value: "Microsoft Excel 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011714" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( excelVer, "^(12\\.)" ) && version_is_less( version: excelVer, test_version: "12.0.6786.5000" )){
	report = report_fixed_ver( file_checked: excelPath + "Excel.exe", file_version: excelVer, vulnerable_range: "12.0 - 12.0.6786.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

