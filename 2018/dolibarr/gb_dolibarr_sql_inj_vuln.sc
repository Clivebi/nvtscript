if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113196" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-24 14:25:13 +0200 (Thu, 24 May 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:36:00 +0000 (Sat, 30 Jan 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-9019", "CVE-2018-10092", "CVE-2018-10094", "CVE-2018-10095" );
	script_name( "Dolibarr < 7.0.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dolibarr is prone to multiple vulnerabilities:

  - SQL Injection (CVE-2018-9019)

  - Arbitrary command execution (CVE-2018-10092)

  - SQL Injection (CVE-2018-10094)

  - Cross-site scripting vulnerability (CVE-2018-10095)" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary code on
the target host." );
	script_tag( name: "affected", value: "Dolibarr through version 7.0.1." );
	script_tag( name: "solution", value: "Update to version 7.0.2." );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/commit/83b762b681c6dfdceb809d26ce95f3667b614739" );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/blob/7.0.2/ChangeLog" );
	exit( 0 );
}
CPE = "cpe:/a:dolibarr:dolibarr";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "7.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.2" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

