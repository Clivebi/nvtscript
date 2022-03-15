if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113328" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-23 14:09:09 +0200 (Wed, 23 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-22 13:51:00 +0000 (Fri, 22 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-11403", "CVE-2018-11404" );
	script_name( "DomainMOD <= 4.09.03 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_domainmod_http_detect.sc" );
	script_mandatory_keys( "domainmod/detected" );
	script_tag( name: "summary", value: "DomainMOD is prone to multiple Cross-Site Scripting (XSS) Vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - XSS via the assets/edit/account-owner.php oid parameter

  - XSS via the assets/edit/ssl-provider-account.php sslpaid parameter" );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to inject
  arbitrary JavaScript and HTML into the page." );
	script_tag( name: "affected", value: "DomainMOD through version 4.09.03" );
	script_tag( name: "solution", value: "Update to version 4.10.0." );
	script_xref( name: "URL", value: "https://github.com/domainmod/domainmod/issues/63" );
	exit( 0 );
}
CPE = "cpe:/a:domainmod:domainmod";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.10.00" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.10.00" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

