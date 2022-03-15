CPE = "cpe:/a:jquery:jquery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143968" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 01:48:46 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-28 13:15:00 +0000 (Thu, 28 May 2020)" );
	script_cve_id( "CVE-2020-7656" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "jQuery < 1.9.0 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jquery_consolidation.sc" );
	script_mandatory_keys( "jquery/detected" );
	script_tag( name: "summary", value: "jQuery is prone to a cross-site scripting (XSS) vulnerability
  via the load method." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "jQuery allows cross-site scripting attacks via the load method.
  The load method fails to recognize and remove '<script>' HTML tags that contain a whitespace
  character, i.e: '</script >', which results in the enclosed script logic to be executed." );
	script_tag( name: "affected", value: "jQuery versions prior to 1.9.0." );
	script_tag( name: "solution", value: "Update to version 1.9.0 or later." );
	script_xref( name: "URL", value: "https://snyk.io/vuln/SNYK-JS-JQUERY-569619" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.9.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.9.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

