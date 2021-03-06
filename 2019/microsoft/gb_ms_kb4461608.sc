if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814741" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-0669" );
	script_bugtraq_id( 106897 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-13 10:47:59 +0530 (Wed, 13 Feb 2019)" );
	script_name( "Microsoft Excel Viewer Security Feature Bypass Vulnerability (KB4461608)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4461608" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when Microsoft
  Excel improperly discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who exploited the vulnerability could use the information to compromise the
  user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Excel Viewer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4461608" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/XLView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
excelviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(!excelviewVer){
	exit( 0 );
}
if(IsMatchRegexp( excelviewVer, "^12\\." ) && version_is_less( version: excelviewVer, test_version: "12.0.6807.5000" )){
	report = report_fixed_ver( file_checked: "Xlview.exe", file_version: excelviewVer, vulnerable_range: "12.0 - 12.0.6807.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

