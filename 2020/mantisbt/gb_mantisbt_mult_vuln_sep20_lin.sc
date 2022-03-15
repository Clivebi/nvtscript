CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144699" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-02 08:20:14 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-13 17:59:00 +0000 (Tue, 13 Oct 2020)" );
	script_cve_id( "CVE-2020-25781", "CVE-2020-25830", "CVE-2020-25288" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.24.3 Multiple Vulnerabilities - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MantisBT is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Access to private bug note attachments (CVE-2020-25781)

  - HTML injection in bug_actiongroup_page.php (CVE-2020-25830)

  - HTML injection on bug_update_page.php (CVE-2020-25288)" );
	script_tag( name: "affected", value: "MantisBT versions 2.24.2 and prior." );
	script_tag( name: "solution", value: "Update to version 2.24.3 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27039" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27304" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27275" );
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
if(version_is_less( version: version, test_version: "2.24.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.24.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

