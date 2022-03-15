if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113394" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-20 11:31:24 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 13:23:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-11870" );
	script_name( "Serendipity < 2.1.5 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "serendipity_detect.sc" );
	script_mandatory_keys( "Serendipity/installed" );
	script_tag( name: "summary", value: "Serendipity is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability can be exploited via EXIF data that is mishandled in the
  templates/2k11/admin/media_choose.tpl Editor Preview feature or the
  templates/2k11/admin/media_items.tpl Media Library feature." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject arbitrary HTML
  or JavaScript into the site." );
	script_tag( name: "affected", value: "Serendipity through version 2.1.4444." );
	script_tag( name: "solution", value: "Update to version 2.1.5." );
	script_xref( name: "URL", value: "https://github.com/s9y/Serendipity/issues/598" );
	script_xref( name: "URL", value: "https://blog.s9y.org/archives/282-Serendipity-2.1.5-released.html" );
	exit( 0 );
}
CPE = "cpe:/a:s9y:serendipity";
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
if(version_is_less( version: version, test_version: "2.1.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

