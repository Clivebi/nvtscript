if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112192" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-16 10:21:08 +0100 (Tue, 16 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-05 21:45:00 +0000 (Mon, 05 Feb 2018)" );
	script_cve_id( "CVE-2018-5688" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ILIAS < 5.2.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ilias_detect.sc" );
	script_mandatory_keys( "ilias/installed" );
	script_tag( name: "summary", value: "ILIAS eLearning before version 5.2.4 is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "insight", value: "Cross-site scripting exists via the cmd parameter to the displayHeader function in setup/classes/class.ilSetupGUI.php in the Setup component." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ILIAS up to and including version 5.2.3." );
	script_tag( name: "solution", value: "Update to version 5.2.4 or later." );
	script_xref( name: "URL", value: "https://www.ilias.de/docu/goto_docu_pg_75029_35.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:ilias:ilias";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

