CPE = "cpe:/a:webmin:webmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145822" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-26 06:14:55 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-28 16:03:00 +0000 (Wed, 28 Apr 2021)" );
	script_cve_id( "CVE-2021-31760", "CVE-2021-31761", "CVE-2021-31762" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "Webmin <= 1.973 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "webmin.sc" );
	script_mandatory_keys( "webmin/installed" );
	script_tag( name: "summary", value: "Webmin is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-31760: Cross Site Request Forgery (CSRF) which might lead to a Remote Command Execution (RCE)
    through Webmin's running process feature

  - CVE-2021-31761: Reflected Cross Site Scripting (XSS) which might lead to an RCE through Webmin's running
    process feature

  - CVE-2021-31762: CSRF to create a privileged user through Webmin's add users feature, and then get a
    reverse shell through Webmin's running process feature" );
	script_tag( name: "affected", value: "Webmin version 1.973 and probably prior." );
	script_tag( name: "solution", value: "No known solution is available as of 26th April, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://github.com/Mesh3l911/CVE-2021-31760" );
	script_xref( name: "URL", value: "https://github.com/Mesh3l911/CVE-2021-31761" );
	script_xref( name: "URL", value: "https://github.com/Mesh3l911/CVE-2021-31762" );
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
if(version_is_less_equal( version: version, test_version: "1.973" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

