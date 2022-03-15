CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813450" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-12581" );
	script_bugtraq_id( 104530 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-10 13:18:00 +0000 (Fri, 10 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-26 12:47:09 +0530 (Tue, 26 Jun 2018)" );
	script_name( "phpMyAdmin Cross-Site Scripting Vulnerability (PMASA-2018-3)-Windows" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin and
  is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient validation
  of input passed to 'js/designer/move.js' script in phpMyAdmin." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to inject arbitrary web script or HTML via crafted database name." );
	script_tag( name: "affected", value: "phpMyAdmin versions prior to 4.8.2 on windows" );
	script_tag( name: "solution", value: "Upgrade to version 4.8.2 or newer. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2018-3" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.8.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.8.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 0 );

