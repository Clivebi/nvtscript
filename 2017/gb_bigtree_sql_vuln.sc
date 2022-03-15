CPE = "cpe:/a:bigtreecms:bigtree_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140256" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-31 12:43:19 +0700 (Mon, 31 Jul 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-02 17:33:00 +0000 (Wed, 02 Aug 2017)" );
	script_cve_id( "CVE-2017-11736" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "BigTree CMS SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_bigtree_detect.sc" );
	script_mandatory_keys( "bigtree_cms/detected" );
	script_tag( name: "summary", value: "BigTree CMS is prone to an SQL injection vulnerability." );
	script_tag( name: "insight", value: "SQL injection vulnerability in core\\admin\\auto-modules\\forms\\process.php in
  BigTree CMS allows remote authenticated users to execute arbitrary SQL commands via the tags array parameter." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 4.2.19 or later." );
	script_xref( name: "URL", value: "https://github.com/bigtreecms/BigTree-CMS/issues/304" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.2.19" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.19" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

