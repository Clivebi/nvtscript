CPE = "cpe:/a:foxitsoftware:reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811501" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_cve_id( "CVE-2017-10994" );
	script_bugtraq_id( 99499 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-24 01:29:00 +0000 (Thu, 24 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-07-11 11:24:37 +0530 (Tue, 11 Jul 2017)" );
	script_name( "Foxit Reader Arbitrary Write RCE Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Foxit Reader
  and is prone to an arbitrary write RCE vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an input validation
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code within the context of the affected
  application. Failed exploit attempts will likely cause a denial-of-service
  condition." );
	script_tag( name: "affected", value: "Foxit Reader version prior to 8.3.1 on
  windows" );
	script_tag( name: "solution", value: "Upgrade to Foxit Reader version 8.3.1 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_reader_detect_portable_win.sc" );
	script_mandatory_keys( "foxit/reader/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!foxitVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: foxitVer, test_version: "8.3.1.21155" )){
	report = report_fixed_ver( installed_version: foxitVer, fixed_version: "8.3.1" );
	security_message( data: report );
	exit( 0 );
}

