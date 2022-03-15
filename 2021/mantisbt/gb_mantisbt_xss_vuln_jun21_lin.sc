CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146150" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 06:08:17 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 13:27:00 +0000 (Mon, 21 Jun 2021)" );
	script_cve_id( "CVE-2021-33557" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.25.2 XSS Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An XSS issue was discovered in manage_custom_field_edit_page.php.
  Unescaped output of the return parameter allows an attacker to inject code into a hidden input field." );
	script_tag( name: "affected", value: "MantisBT through version 2.25.1." );
	script_tag( name: "solution", value: "Update to version 2.25.2 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=28552" );
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
if(version_is_less( version: version, test_version: "2.25.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.25.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

