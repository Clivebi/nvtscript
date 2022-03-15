if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113644" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-02-21 09:31:31 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-07 01:30:00 +0000 (Sat, 07 Mar 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-20107", "CVE-2020-8841" );
	script_name( "TestLink <= 1.9.19 Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "testlink_detect.sc" );
	script_mandatory_keys( "testlink/detected" );
	script_tag( name: "summary", value: "TestLink is prone to multiple SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "TestLink is prone to multiple authenticated SQL injection vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  read or modify sensitive information or even execute arbitrary commands on the target system." );
	script_tag( name: "affected", value: "TestLink version 1.9.19 and prior." );
	script_tag( name: "solution", value: "Update to version 1.9.20 or later." );
	script_xref( name: "URL", value: "https://github.com/ver007/testlink-1.9.19-sqlinject" );
	script_xref( name: "URL", value: "http://mantis.testlink.org/view.php?id=8829" );
	exit( 0 );
}
CPE = "cpe:/a:testlink:testlink";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.9.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.9.20", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

