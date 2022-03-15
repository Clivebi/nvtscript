CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141823" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-04 11:04:34 +0700 (Fri, 04 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-09 13:12:00 +0000 (Wed, 09 Jan 2019)" );
	script_cve_id( "CVE-2018-19992", "CVE-2018-19993", "CVE-2018-19994", "CVE-2018-19995", "CVE-2018-19998" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dolibarr < 8.0.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dolibarr is prone to multiple vulnerabilities:

  - A stored cross-site scripting (XSS) vulnerability allows remote authenticated users to inject arbitrary web
script or HTML via the 'address' (POST) or 'town' (POST) parameter to adherents/type.php (CVE-2018-19992)

  - A reflected cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or
HTML via the transphrase parameter to public/notice.php (CVE-2018-19993)

  - An error-based SQL injection vulnerability in product/card.php allows remote authenticated users to execute
arbitrary SQL commands via the desiredstock parameter (CVE-2018-19994)

  - A stored cross-site scripting (XSS) vulnerability allows remote authenticated users to inject arbitrary web
script or HTML via the 'address' (POST) or 'town' (POST) parameter to user/card.php (CVE-2018-19995)

  - SQL injection vulnerability in user/card.php allows remote authenticated users to execute arbitrary SQL
commands via the employee parameter (CVE-2018-19998)" );
	script_tag( name: "affected", value: "Dolibarr prior to version 8.0.4." );
	script_tag( name: "solution", value: "Update to version 8.0.4 or later." );
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
if(version_is_less( version: version, test_version: "8.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

