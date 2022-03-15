if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817729" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_cve_id( "CVE-2021-34518", "CVE-2021-34501" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 14:48:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-14 16:26:31 +0530 (Wed, 14 Jul 2021)" );
	script_name( "Microsoft Excel 2016 RCE Vulnerabilities (KB5001977)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB5001977" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaws exist due to an improper input validation
  in Microsoft Office software." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Excel 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5001977" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
vers = get_kb_item( "SMB/Office/Excel/Version" );
if(!vers){
	exit( 0 );
}
path = get_kb_item( "SMB/Office/Excel/Install/Path" );
if(!path){
	path = "Unable to fetch the install path";
}
if(version_in_range( version: vers, test_version: "16.0", test_version2: "16.0.5188.0999" )){
	report = report_fixed_ver( file_checked: path + "Excel.exe", file_version: vers, vulnerable_range: "16.0 - 16.0.5188.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

