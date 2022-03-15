CPE = "cpe:/a:hp:loadrunner";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810934" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2016-4384" );
	script_bugtraq_id( 93069 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-20 16:22:23 +0530 (Thu, 20 Apr 2017)" );
	script_name( "HPE LoadRunner Unspecified Remote DoS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with HPE LoadRunner
  and is prone to a remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to cause a denial-of-service condition." );
	script_tag( name: "affected", value: "HPE LoadRunner versions prior to 12.50
  patch 3." );
	script_tag( name: "solution", value: "Upgrade to HPE LoadRunner version
  12.50 patch 3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "30" );
	script_xref( name: "URL", value: "https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05278882" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_hpe_loadrunner_detect.sc" );
	script_mandatory_keys( "HPE/LoadRunner/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!hpVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: hpVer, test_version: "12.50" )){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: "12.50 patch 3" );
	security_message( data: report );
	exit( 0 );
}

