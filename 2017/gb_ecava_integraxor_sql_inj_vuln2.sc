CPE = "cpe:/a:ecava:integraxor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106888" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-21 11:05:39 +0700 (Wed, 21 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_cve_id( "CVE-2017-6050" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ECAVA IntegraXor SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ecava_integraxor_detect.sc" );
	script_mandatory_keys( "EcavaIntegraXor/Installed" );
	script_tag( name: "summary", value: "ECAVA IntegraXor is prone to multiple SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The application fails to properly validate user input, which may allow for
an unauthenticated attacker to remotely execute arbitrary code in the form of SQL queries." );
	script_tag( name: "affected", value: "IntegraXor Versions 5.2.1231.0 and prior." );
	script_tag( name: "solution", value: "Update to 6.0.522.1 or later versions." );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-17-171-01" );
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
if(version_is_less_equal( version: version, test_version: "5.2.1231.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.522.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

