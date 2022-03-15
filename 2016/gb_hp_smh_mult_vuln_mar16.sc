CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807526" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-1993", "CVE-2016-1994", "CVE-2016-1995", "CVE-2016-1996" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-22 12:10:54 +0530 (Tue, 22 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities(mar-2016)" );
	script_tag( name: "summary", value: "The host is installed with HP System
  Management Homepage (SMH) and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to obtain and modify sensitive information and also remote attackers to execute
  arbitrary code and to obtain sensitive information." );
	script_tag( name: "affected", value: "HP System Management Homepage before 7.5.4" );
	script_tag( name: "solution", value: "Upgrade to HP System Management Homepage
  7.5.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05045763" );
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
if(version_is_less( version: smhVer, test_version: "7.5.4" )){
	report = report_fixed_ver( installed_version: smhVer, fixed_version: "7.5.4" );
	security_message( data: report, port: smhPort );
	exit( 0 );
}

