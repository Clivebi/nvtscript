CPE = "cpe:/a:hp:service_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106126" );
	script_version( "2019-09-16T06:54:58+0000" );
	script_tag( name: "last_modification", value: "2019-09-16 06:54:58 +0000 (Mon, 16 Sep 2019)" );
	script_tag( name: "creation_date", value: "2016-07-11 15:18:31 +0700 (Mon, 11 Jul 2016)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-4371" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP Service Manager Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hp_service_manager_detect.sc" );
	script_mandatory_keys( "hp_service_manager/detected" );
	script_tag( name: "summary", value: "HP Service Manager is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote authenticated users may obtain sensitive information, modify data,
and conduct server-side request forgery (SSRF) attacks via unspecified vectors." );
	script_tag( name: "impact", value: "Authenticated attackers may obtain sensitive information, modify data
or conduct server-side request forgery attacks." );
	script_tag( name: "affected", value: "Versions 9.30, 9.31, 9.32, 9.33, 9.34, 9.35, 9.40, and 9.41" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05167176" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.30.0000", test_version2: "9.35.0000" ) || version_in_range( version: version, test_version: "9.40.0000", test_version2: "9.41.0000" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

