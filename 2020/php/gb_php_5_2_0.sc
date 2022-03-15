CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108860" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2006-1015", "CVE-2006-1549", "CVE-2006-2660", "CVE-2006-4486", "CVE-2006-4625", "CVE-2006-4812", "CVE-2006-5465", "CVE-2006-5706", "CVE-2006-7205", "CVE-2007-0448", "CVE-2007-1381", "CVE-2007-1584", "CVE-2007-1888", "CVE-2007-2844", "CVE-2007-5424" );
	script_bugtraq_id( 20349, 20879, 49634 );
	script_name( "PHP < 5.2.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "PHP before version 5.2.0." );
	script_tag( name: "solution", value: "Update PHP to version 5.2.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "5.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

