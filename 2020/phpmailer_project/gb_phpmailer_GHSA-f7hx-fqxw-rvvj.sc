CPE = "cpe:/a:phpmailer_project:phpmailer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144109" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-15 08:43:45 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 20:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_cve_id( "CVE-2020-13625" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "PHPMailer < 6.1.6 Output Escaping Vulnerability" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpmailer_detect.sc" );
	script_mandatory_keys( "phpmailer/detected" );
	script_tag( name: "summary", value: "PHPMailer contains an output escaping bug when the name of a file attachment
  contains a double quote character. This can result in the file type being misinterpreted by the receiver or
  any mail relay processing the message." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PHPMailer versions prior to 6.1.6." );
	script_tag( name: "solution", value: "Update to version 6.1.6 or later." );
	script_xref( name: "URL", value: "https://github.com/PHPMailer/PHPMailer/security/advisories/GHSA-f7hx-fqxw-rvvj" );
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
if(version_is_less( version: version, test_version: "6.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

