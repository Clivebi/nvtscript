CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142172" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-25 08:09:24 +0000 (Tue, 25 Jun 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-09 18:57:00 +0000 (Sun, 09 Jun 2019)" );
	script_cve_id( "CVE-2018-9839" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.13.2 Information Disclosure Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "MantisBT is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Using a crafted request on bug_report_page.php (modifying the 'm_id'
  parameter), any user with REPORTER access or above is able to view any private issue's details (summary,
  description, steps to reproduce, additional information) when cloning it. By checking the 'Copy issue notes'
  and 'Copy attachments' checkboxes and completing the clone operation, this data also becomes public (except
  private notes)." );
	script_tag( name: "affected", value: "MantisBT versions 1.3.0 through 2.13.1." );
	script_tag( name: "solution", value: "Update to version 2.13.2 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=24221" );
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
path = infos["location"];
if(version_in_range( version: version, test_version: "1.3.0", test_version2: "2.13.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.13.2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

