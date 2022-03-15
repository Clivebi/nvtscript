if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113335" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-13 11:26:40 +0200 (Wed, 13 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-20 14:59:00 +0000 (Thu, 20 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-1000011" );
	script_name( "MyWebSQL <= 3.6 Cross-Site Scripting (XSS) Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mywebsql_http_detect.sc" );
	script_mandatory_keys( "mywebsql/detected" );
	script_tag( name: "summary", value: "MyWebSQL is prone to a Cross-Site Scripting (XSS) Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists within the database manager component." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject
  arbitrary JavaScript or HTML into the site." );
	script_tag( name: "affected", value: "MyWebSQL through version 3.6." );
	script_tag( name: "solution", value: "Update to version 3.7." );
	script_xref( name: "URL", value: "https://github.com/Samnan/MyWebSQL" );
	exit( 0 );
}
CPE = "cpe:/a:mywebsql:mywebsql";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "3.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.7" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

