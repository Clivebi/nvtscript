CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106611" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-20 13:33:44 +0700 (Mon, 20 Feb 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-22 17:49:00 +0000 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-5364" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT XSS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cross-site scripting (XSS) vulnerability in
manage_custom_field_edit_page.php allows remote attackers to inject arbitrary web script or HTML via the return
parameter." );
	script_tag( name: "impact", value: "An authenticated attacker may conduct a cross-site scripting attack." );
	script_tag( name: "affected", value: "MantisBT version 1.2.19 and prior." );
	script_tag( name: "solution", value: "Update to MantisBT 1.2.20 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=20956" );
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
if(version_is_less( version: version, test_version: "1.2.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.20" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

