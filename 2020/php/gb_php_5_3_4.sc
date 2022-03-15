CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108870" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-7243", "CVE-2010-2094", "CVE-2010-2950", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150", "CVE-2010-4156", "CVE-2010-4409", "CVE-2010-4697", "CVE-2010-4698", "CVE-2010-4699", "CVE-2010-4700", "CVE-2011-0753", "CVE-2011-0754", "CVE-2011-0755" );
	script_bugtraq_id( 40173, 43926, 44605, 44718, 44723, 44951, 44980, 45119, 45335, 45338, 45339, 45952, 45954, 46056, 46168 );
	script_name( "PHP < 5.3.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "PHP before version 5.3.4." );
	script_tag( name: "solution", value: "Update PHP to version 5.3.4 or later." );
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
if(version_is_less( version: version, test_version: "5.3.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

