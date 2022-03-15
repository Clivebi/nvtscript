CPE = "cpe:/a:sixapart:movable_type";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805369" );
	script_version( "$Revision: 12861 $" );
	script_cve_id( "CVE-2015-0845" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-21 10:53:04 +0100 (Fri, 21 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-22 16:50:00 +0530 (Wed, 22 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Movable Type Templates Arbitrary Code Execution Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with movable type
  and is prone to arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to the  format string
  specifiers are not properly sanitized in user-supplied input. This may
  allow a remote attacker to cause a denial of service or potentially execute
  arbitrary code." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated remote attacker to execute arbitrary code in an affected site." );
	script_tag( name: "affected", value: "Movable Type before 5.2.13" );
	script_tag( name: "solution", value: "Upgrade to Movable Type 5.2.13." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://movabletype.org/news/2015/04/movable_type_608_and_5213_released_to_close_security_vulnera.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mt_detect.sc" );
	script_mandatory_keys( "movabletype/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!movVer = get_app_version( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(version_is_less( version: movVer, test_version: "5.2.13" )){
	report = report_fixed_ver( installed_version: movVer, fixed_version: "5.2.13" );
	security_message( data: report, port: http_port );
	exit( 0 );
}
exit( 99 );

