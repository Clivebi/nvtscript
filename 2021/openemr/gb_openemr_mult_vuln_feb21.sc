CPE = "cpe:/a:open-emr:openemr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112865" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-16 11:51:11 +0000 (Tue, 16 Feb 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 18:01:00 +0000 (Mon, 22 Feb 2021)" );
	script_cve_id( "CVE-2020-29139", "CVE-2020-29140", "CVE-2020-29142", "CVE-2020-29143", "CVE-2021-32101", "CVE-2021-32102", "CVE-2021-32103", "CVE-2021-32104" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenEMR < 5.0.2-5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openemr_detect.sc" );
	script_mandatory_keys( "openemr/installed" );
	script_tag( name: "summary", value: "OpenEMR is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-29139: SQL injection in interface/main/finder/patient_select.php from library/patient.inc

  - CVE-2020-29140: SQL injection in interface/reports/immunization_report.php

  - CVE-2020-29142: SQL injection in interface/usergroup/usergroup_admin.php

  - CVE-2020-29143: SQL injection in interface/reports/non_reported.php

  - CVE-2021-32101: Incorrect access control system in portal/patient/_machine_config.php

  - CVE-2021-32102: SQL injection in library/custom_template/ajax_code.php

  - CVE-2021-32103: Stored XSS in interface/usergroup/usergroup_admin.php

  - CVE-2021-32104: SQL injection in interface/forms/eye_mag/save.php" );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote authenticated
  attacker to execute arbitrary SQL commands via various parameters." );
	script_tag( name: "affected", value: "OpenEMR prior to version 5.0.2-5." );
	script_tag( name: "solution", value: "Update to version 5.0.2-5 or later." );
	script_xref( name: "URL", value: "https://murat.one/?p=70" );
	script_xref( name: "URL", value: "https://murat.one/?p=86" );
	script_xref( name: "URL", value: "https://murat.one/?p=90" );
	script_xref( name: "URL", value: "https://murat.one/?p=94" );
	script_xref( name: "URL", value: "https://blog.sonarsource.com/openemr-5-0-2-1-command-injection-vulnerability" );
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
if(version_is_less( version: version, test_version: "5.0.2-5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.2-5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

