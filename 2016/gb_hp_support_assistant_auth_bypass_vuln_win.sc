CPE = "cpe:/a:hp:support_assistant";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807805" );
	script_version( "2019-07-05T08:56:43+0000" );
	script_cve_id( "CVE-2016-2245" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 08:56:43 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-04-20 17:05:22 +0530 (Wed, 20 Apr 2016)" );
	script_name( "HP Support Assistant Authentication Bypass Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with HP Support
  Assistant and is prone to authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to bypass authentication and get administrative privileges." );
	script_tag( name: "affected", value: "HP Support Assistant version 8.1.40.3 and
  prior on Windows." );
	script_tag( name: "solution", value: "Upgrade to HP Support Assistant version
  8.1.52.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c05031674" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hp_support_assistant_detect.sc" );
	script_mandatory_keys( "HP/Support/Assistant/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!hpVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: hpVer, test_version: "8.1.52.1" )){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: "8.1.52.1" );
	security_message( data: report );
	exit( 0 );
}

