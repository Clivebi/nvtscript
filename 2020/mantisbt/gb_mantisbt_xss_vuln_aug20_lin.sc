CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144390" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-08-13 09:11:09 +0000 (Thu, 13 Aug 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 18:29:00 +0000 (Mon, 17 Aug 2020)" );
	script_cve_id( "CVE-2020-16266" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.24.2 XSS Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Improper escaping on view_all_bug_page.php allows a remote attacker to inject
  arbitrary HTML into the page by saving it into a text Custom Field, leading to possible code execution in the
  browser of any user subsequently viewing the issue (if CSP settings allow it)." );
	script_tag( name: "affected", value: "MantisBT versions 2.24.1 and prior." );
	script_tag( name: "solution", value: "Update to version 2.24.2 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/blog/archives/mantisbt/665" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27056" );
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
if(version_is_less( version: version, test_version: "2.24.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.24.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

