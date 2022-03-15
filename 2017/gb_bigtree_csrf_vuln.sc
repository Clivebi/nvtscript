CPE = "cpe:/a:bigtreecms:bigtree_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106666" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-17 13:15:28 +0700 (Fri, 17 Mar 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-16 16:00:00 +0000 (Thu, 16 Mar 2017)" );
	script_cve_id( "CVE-2017-6914", "CVE-2017-6915", "CVE-2017-6916", "CVE-2017-6917", "CVE-2017-6918" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "BigTree CMS Multiple CSRF Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_bigtree_detect.sc" );
	script_mandatory_keys( "bigtree_cms/detected" );
	script_tag( name: "summary", value: "BigTree CMS is prone to multiple CSRF vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "BigTree CMS is prone to multiple CSRF vulnerabilities:

  - CSRF with the id parameter to the admin/ajax/users/delete/ page. (CVE-2017-6914)

  - CSRF with the colophon parameter to the admin/settings/update/ page. (CVE-2017-6915)

  - CSRF with the nav-social[#] parameter to the admin/settings/update/ page. (CVE-2017-6916)

  - CSRF with the value parameter to the admin/settings/update/ page. (CVE-2017-6917)

  - CSRF with the value[#][*] parameter to the admin/settings/update/ page. (CVE-2017-6918)" );
	script_tag( name: "affected", value: "BigTree CMS 4.1.18 and 4.2.16." );
	script_tag( name: "solution", value: "Update to version 4.2.17 or later." );
	script_xref( name: "URL", value: "https://github.com/bigtreecms/BigTree-CMS/issues/275" );
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
if(version_is_less( version: version, test_version: "4.2.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.17" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

