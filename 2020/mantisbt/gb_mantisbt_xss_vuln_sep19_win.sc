CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143620" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-03-20 03:21:05 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-24 17:16:00 +0000 (Tue, 24 Mar 2020)" );
	script_cve_id( "CVE-2019-15539" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.21.3 XSS Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The proj_doc_edit_page.php Project Documentation feature has a stored
  cross-site scripting (XSS) vulnerability, allowing execution of arbitrary code (if CSP settings permit it) after
  uploading an attachment with a crafted filename. The code is executed when editing the document's page." );
	script_tag( name: "affected", value: "MantisBT versions 2.21.2 and prior." );
	script_tag( name: "solution", value: "Update to version 2.21.3 or later." );
	script_xref( name: "URL", value: "https://github.com/mantisbt/mantisbt/commit/bd094dede74ff6e313e286e949e2387233a96eea" );
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
if(version_is_less( version: version, test_version: "2.21.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.21.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

