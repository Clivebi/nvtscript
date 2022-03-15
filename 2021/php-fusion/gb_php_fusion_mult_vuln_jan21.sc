CPE = "cpe:/a:php-fusion:php-fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145876" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-03 09:37:53 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 17:51:00 +0000 (Tue, 02 Feb 2021)" );
	script_cve_id( "CVE-2020-35687", "CVE-2020-35952" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHPFusion < 9.03.100 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_mandatory_keys( "php-fusion/detected" );
	script_tag( name: "summary", value: "PHPFusion is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-35687: CSRF attack leads to deletion of shoutbox messages

  - CVE-2020-35952: User enumeration in Sign in page" );
	script_tag( name: "affected", value: "PHPFusion through version 9.03.90." );
	script_tag( name: "solution", value: "Update to version 9.03.100 or later." );
	script_xref( name: "URL", value: "https://github.com/PHPFusion/PHPFusion/issues/2347" );
	script_xref( name: "URL", value: "https://github.com/PHPFusion/PHPFusion/issues/2346" );
	exit( 0 );
}
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
if(version_is_less( version: version, test_version: "9.03.100" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.03.100", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

