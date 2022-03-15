CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114127" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-03 14:56:41 +0200 (Tue, 03 Sep 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-02-25 17:41:00 +0000 (Thu, 25 Feb 2016)" );
	script_cve_id( "CVE-2015-8794" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail < 1.0.6 And 1.1.x < 1.1.2 Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to a directory traversal vulnerability." );
	script_tag( name: "insight", value: "This absolute path traversal vulnerability in program/steps/addressbook/photo.inc
  allows remote authenticated users to read arbitrary files via a full pathname in the _alt parameter,
  related to contact photo handling." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions before 1.0.6 and 1.1.x before 1.1.2." );
	script_tag( name: "solution", value: "Update to version 1.1.2, or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/4817" );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "1.0.6" ) || version_is_less_equal( version: version, test_version: "1.1" ) || version_in_range( version: version, test_version: "1.1beta", test_version2: "1.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

