CPE = "cpe:/a:phpmailer_project:phpmailer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108467" );
	script_version( "2021-09-29T11:39:12+0000" );
	script_cve_id( "CVE-2015-8476" );
	script_bugtraq_id( 78619 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 11:39:12 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-09-25 09:59:32 +0200 (Tue, 25 Sep 2018)" );
	script_name( "PHPMailer < 5.2.14 SMTP CRLF Injection Vulnerability" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpmailer_detect.sc" );
	script_mandatory_keys( "phpmailer/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/78619" );
	script_xref( name: "URL", value: "https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md" );
	script_tag( name: "summary", value: "PHPMailer is prone to a SMTP CRLF injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because PHPMailer allows to inject arbitrary SMTP
  commands via CRLF sequences in an (1) email address to the validateAddress function in class.phpmailer.php
  or (2) SMTP command to the sendCommand function in class.smtp.php." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to send arbitrary messages." );
	script_tag( name: "affected", value: "PHPMailer versions before 5.2.14 are vulnerable." );
	script_tag( name: "solution", value: "Update to version 5.2.14 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: version, test_version: "5.2.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.14", install_url: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

