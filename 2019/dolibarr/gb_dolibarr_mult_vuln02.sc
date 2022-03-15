CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142133" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-12 10:05:32 +0700 (Tue, 12 Mar 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 15:20:00 +0000 (Fri, 08 Mar 2019)" );
	script_cve_id( "CVE-2018-16808", "CVE-2018-16809" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dolibarr < 7.0.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dolibarr is prone to multiple vulnerabilities:

  - Stored XSS vulnerability in expense report plugin (CVE-2018-16808)

  - SQL Injection vulnerabilityh in expense report plugin (CVE-2018-16809)" );
	script_tag( name: "affected", value: "Dolibarr prior to version 7.0.1." );
	script_tag( name: "solution", value: "Update to version 7.0.1 or later." );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/issues/9449" );
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
if(version_is_less( version: version, test_version: "7.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

