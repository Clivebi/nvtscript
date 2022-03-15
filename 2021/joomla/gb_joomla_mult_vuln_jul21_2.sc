CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146242" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-08 04:48:56 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-09 17:49:00 +0000 (Fri, 09 Jul 2021)" );
	script_cve_id( "CVE-2021-26036", "CVE-2021-26037", "CVE-2021-26038" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla! 2.5.0 - 3.9.27 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "Joomla! is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-26036: Missing validation of input could lead to a broken usergroups table.

  - CVE-2021-26037: CMS functions did not properly terminate existing user sessions when a user's
  password was changed or the user was blocked.

  - CVE-2021-26038: Install action in com_installer lack the required hardcoded ACL checks for
  superusers. A default system is not affected cause the default ACL for com_installer is limited
  to super users already." );
	script_tag( name: "affected", value: "Joomla! version 2.5.0 through 3.9.27." );
	script_tag( name: "solution", value: "Update to version 3.9.28 or later." );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre.html" );
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
if(version_in_range( version: version, test_version: "2.5.0", test_version2: "3.9.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.28", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

