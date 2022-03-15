CPE = "cpe:/a:phpmailer_project:phpmailer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106987" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-27 15:21:49 +0700 (Thu, 27 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-03 17:14:00 +0000 (Fri, 03 May 2019)" );
	script_cve_id( "CVE-2017-11503" );
	script_bugtraq_id( 99293 );
	script_name( "PHPMailer XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpmailer_detect.sc" );
	script_mandatory_keys( "phpmailer/detected" );
	script_xref( name: "URL", value: "https://github.com/PHPMailer/PHPMailer/releases" );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2017060181" );
	script_xref( name: "URL", value: "https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md" );
	script_tag( name: "summary", value: "PHPMailer is prone to a cross-site scripting vulneragility in the
  'From Email Address' and 'To Email Address' fields of code_generator.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PHPMailer version 5.2.23 and prior." );
	script_tag( name: "solution", value: "Update to version 5.2.24 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "5.2.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.24", install_url: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

