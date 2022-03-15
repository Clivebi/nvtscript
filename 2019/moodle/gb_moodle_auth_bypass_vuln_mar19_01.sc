if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113363" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-02 12:42:10 +0000 (Tue, 02 Apr 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-3852" );
	script_name( "Moodle CMS 3.6.x <= 3.6.2 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle CMS is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The get_with_capability_join and get_users_by capability functions are
  not taking context freezing into account when checking user capabilities." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to read sensitive information." );
	script_tag( name: "affected", value: "Moodle CMS version 3.6.0 through 3.6.2." );
	script_tag( name: "solution", value: "Update to version 3.6.3." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=384015#p1547748" );
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
if(version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

