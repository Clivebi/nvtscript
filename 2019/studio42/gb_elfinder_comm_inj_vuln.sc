if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112522" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-28 11:07:11 +0100 (Thu, 28 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-9194" );
	script_name( "elFinder < 2.1.48 Command Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elfinder_detect.sc" );
	script_mandatory_keys( "studio42/elfinder/detected" );
	script_tag( name: "summary", value: "elFinder is prone to a command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability lies in the PHP connector of the application." );
	script_tag( name: "impact", value: "Successful exploitation would allow a remote attacker to inject commands." );
	script_tag( name: "affected", value: "elFinder through version 2.1.47." );
	script_tag( name: "solution", value: "Update to version 2.1.48." );
	script_xref( name: "URL", value: "https://github.com/Studio-42/elFinder/releases/tag/2.1.48" );
	script_xref( name: "URL", value: "https://github.com/Studio-42/elFinder/compare/6884c4f...0740028" );
	exit( 0 );
}
CPE = "cpe:/a:studio42:elfinder";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.1.48" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.48" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

