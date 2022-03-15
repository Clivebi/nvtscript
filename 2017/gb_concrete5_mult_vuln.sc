CPE = "cpe:/a:concrete5:concrete5";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112039" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-11 08:49:26 +0200 (Mon, 11 Sep 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-13 17:47:00 +0000 (Wed, 13 Sep 2017)" );
	script_cve_id( "CVE-2015-4721", "CVE-2015-4724" );
	script_bugtraq_id( 96891 );
	script_name( "Concrete5 <= 5.7.3.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "Concrete5 is prone to multiple cross-site scripting and SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Concrete5 versions up to and including 5.7.3.1." );
	script_tag( name: "solution", value: "Update to version 5.7.4." );
	script_xref( name: "URL", value: "https://hackerone.com/reports/59664" );
	script_xref( name: "URL", value: "https://hackerone.com/reports/59661" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "5.7.3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.7.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

