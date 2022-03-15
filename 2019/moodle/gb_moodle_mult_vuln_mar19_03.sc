if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113364" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-02 12:55:13 +0000 (Tue, 02 Apr 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-04 15:29:00 +0000 (Thu, 04 Apr 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-3847", "CVE-2019-3850" );
	script_name( "Moodle CMS <= 3.1.16, 3.4.x <= 3.4.7, 3.5.x <= 3.5.4 and 3.6.x <= 3.6.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle CMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Users with the 'login as other users' capability (such as administrators/managers) can access other users'
  Dashboards, but the JavaScript those other users may have added to their Dashboard is not being escaped when
  being viewed by the user logging in on their behalf.

  - Links within assignment submission comments open directly in the same window." );
	script_tag( name: "impact", value: "An attacker might be able to steal session or cookie related info,
  or inject a malicious link to steal information or distribute malware." );
	script_tag( name: "affected", value: "Moodle CMS versions through 3.1.16, 3.4.0 through 3.4.7, 3.5.0 through 3.5.4 and 3.6.0 through 3.6.2." );
	script_tag( name: "solution", value: "Update to version 3.1.17, 3.4.8, 3.5.5 or 3.6.3 respectively." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=384013#p1547745" );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=384010" );
	exit( 0 );
}
CPE = "cpe:/a:moodle:moodle";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.1.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.17" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.8" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.5" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

