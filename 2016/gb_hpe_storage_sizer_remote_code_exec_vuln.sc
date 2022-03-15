CPE = "cpe:/a:hp:storage_sizing_tool";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809187" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2016-4377" );
	script_bugtraq_id( 92479 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:17:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2016-09-01 16:12:15 +0530 (Thu, 01 Sep 2016)" );
	script_name( "HPE Storage Sizer Remote Arbitrary Code Execution Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with HPE Storage
  Sizer and is prone to remote arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  arbitrary code execution." );
	script_tag( name: "affected", value: "HPE Storage Sizer prior to 13.0." );
	script_tag( name: "solution", value: "Upgrade to HPE Storage Sizer version
  13.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05237578" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_hpe_storage_sizer_detect.sc" );
	script_mandatory_keys( "HPE/Storage/Sizer/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!hpVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: hpVer, test_version: "13.0" )){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: "13.0" );
	security_message( data: report );
	exit( 0 );
}

