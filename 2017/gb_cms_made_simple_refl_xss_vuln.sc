CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112120" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-13 14:05:33 +0100 (Mon, 13 Nov 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-22 17:25:00 +0000 (Wed, 22 Nov 2017)" );
	script_cve_id( "CVE-2017-16784" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CMS Made Simple 2.2.2 Reflected XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to a reflected cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There is reflected XSS via the cntnt01detailtemplate parameter." );
	script_tag( name: "affected", value: "CMS Made Simple version 2.2.2." );
	script_tag( name: "solution", value: "Upgrade to version 2.2.3 or later." );
	script_xref( name: "URL", value: "https://www.netsparker.com/web-applications-advisories/ns-17-031-reflected-xss-vulnerability-in-cms-made-simple/" );
	script_xref( name: "URL", value: "https://www.cmsmadesimple.org/" );
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
if(version_is_equal( version: version, test_version: "2.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

