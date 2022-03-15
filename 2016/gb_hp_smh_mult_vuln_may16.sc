CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807598" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2011-4969", "CVE-2015-3194", "CVE-2015-3195", "CVE-2016-0705", "CVE-2016-0799", "CVE-2016-2842", "CVE-2015-3237", "CVE-2015-7995", "CVE-2015-8035", "CVE-2007-6750", "CVE-2016-2015" );
	script_bugtraq_id( 58458, 78623, 78626, 75387, 77325, 77390, 21865 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-20 16:59:00 +0000 (Wed, 20 Feb 2019)" );
	script_tag( name: "creation_date", value: "2016-05-19 15:47:50 +0530 (Thu, 19 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities(may-2016)" );
	script_tag( name: "summary", value: "The host is installed with HP System
  Management Homepage (SMH) and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to obtain and modify sensitive information and also remote attackers to execute
  arbitrary code and to obtain sensitive information." );
	script_tag( name: "affected", value: "HP System Management Homepage before 7.5.5" );
	script_tag( name: "solution", value: "Upgrade to HP System Management Homepage
  7.5.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05111017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_xref( name: "URL", value: "http://www8.hp.com/us/en/products/server-software/product-detail.html?oid=344313" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!smhPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!smhVer = get_app_version( cpe: CPE, port: smhPort )){
	exit( 0 );
}
if(version_is_less( version: smhVer, test_version: "7.5.5" )){
	report = report_fixed_ver( installed_version: smhVer, fixed_version: "7.5.5" );
	security_message( data: report, port: smhPort );
	exit( 0 );
}

