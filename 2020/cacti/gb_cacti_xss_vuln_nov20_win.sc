if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113782" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-11-13 15:42:58 +0000 (Fri, 13 Nov 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-23 17:18:00 +0000 (Mon, 23 Nov 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-25706" );
	script_name( "Cacti < 1.2.14 XSS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Cacti is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists due to
  improper escaping of error messages during template import preview in the xml_path field." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  inject arbitrary HTML or JavaScript into the site." );
	script_tag( name: "affected", value: "Cacti through version 1.2.13." );
	script_tag( name: "solution", value: "Update to version 1.2.14 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/3723" );
	exit( 0 );
}
CPE = "cpe:/a:cacti:cacti";
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
if(version_is_less( version: version, test_version: "1.2.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.14", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );
