CPE = "cpe:/a:hp:loadrunner";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810936" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2013-6213" );
	script_bugtraq_id( 66961 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2017-04-21 10:33:34 +0530 (Fri, 21 Apr 2017)" );
	script_name( "HPE LoadRunner Virtual User Generator Remote Code Execution Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with HPE LoadRunner
  and is prone to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified
  error in 'Virtual User Generator'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to execute arbitrary code via unknown vectors." );
	script_tag( name: "affected", value: "HPE LoadRunner versions before 11.52
  Patch 1" );
	script_tag( name: "solution", value: "Upgrade to HPE LoadRunner 11.52 Patch 1 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "30" );
	script_xref( name: "URL", value: "http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03969437" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
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
if(version_is_less_equal( version: hpVer, test_version: "11.52" )){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: "11.52 Patch 1" );
	security_message( data: report );
	exit( 0 );
}

