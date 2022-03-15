CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106933" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-07 15:56:34 +0700 (Fri, 07 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-17 13:18:00 +0000 (Mon, 17 Jul 2017)" );
	script_cve_id( "CVE-2017-10970", "CVE-2017-11163" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti XSS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Cross-site scripting (XSS) vulnerability in link.php in Cacti allows remote
anonymous users to inject arbitrary web script or HTML via the id parameter, related to the die_html_input_error
function in lib/html_validate.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Cacti version 1.1.12 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 1.1.13 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/838" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/847" );
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
if(version_is_less( version: version, test_version: "1.1.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.13" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
