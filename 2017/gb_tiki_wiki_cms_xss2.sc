CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106962" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-18 11:04:20 +0700 (Tue, 18 Jul 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-05 17:09:00 +0000 (Wed, 05 Jul 2017)" );
	script_cve_id( "CVE-2017-9145" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tiki Wiki CMS Groupware XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	script_tag( name: "summary", value: "TikiFilter.php in Tiki Wiki CMS Groupware does not properly validate the
imgsize or lang parameter to prevent XSS." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware 12.x through 16.x." );
	script_tag( name: "solution", value: "Upgrade to version 17.0 or later." );
	script_xref( name: "URL", value: "https://sourceforge.net/p/tikiwiki/code/62386" );
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
if(version_in_range( version: version, test_version: "12", test_version2: "16.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

