if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112532" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-06 11:13:00 +0100 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-28 14:11:00 +0000 (Mon, 28 Jan 2019)" );
	script_cve_id( "CVE-2019-6780" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Wise Chat Plugin < 2.7 Mashandling of External Links Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/wise-chat/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Wise Chat mishandles external links because
  rendering/filters/post/WiseChatLinksPostFilter.php omits noopener and noreferrer." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "WordPress Wise Chat plugin before version 2.7." );
	script_tag( name: "solution", value: "Update to version 2.7 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wise-chat/#developers" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/46247" );
	script_xref( name: "URL", value: "https://plugins.trac.wordpress.org/changeset/2016929/wise-chat/trunk/src/rendering/filters/post/WiseChatLinksPostFilter.php" );
	exit( 0 );
}
CPE = "cpe:/a:kainex:wise-chat";
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
if(version_is_less( version: version, test_version: "2.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

