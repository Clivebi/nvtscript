CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112119" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-13 13:56:33 +0100 (Mon, 13 Nov 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-21 17:48:00 +0000 (Thu, 21 Nov 2019)" );
	script_cve_id( "CVE-2017-16798", "CVE-2017-16799" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CMS Made Simple 2.2.3.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "CMS Made Simple is prone to multiple vulnerabilities:

  - The is_file_acceptable function in modules/FileManager/action.upload.php only blocks file extensions that begin or end with a 'php' substring,
which allows remote attackers to bypass intended access restrictions or trigger XSS via other extensions, as demonstrated by .phtml, .pht, .html, or .svg. (CVE-2017-16798)

  - In modules/New/action.addcategory.php, stored XSS is possible via the m1_name parameter to admin/moduleinterface.php during addition of a category,
a related issue to CVE-2010-3882. (CVE-2017-16799)" );
	script_tag( name: "affected", value: "CMS Made Simple version 2.2.3.1." );
	script_tag( name: "solution", value: "Upgrade to CMS Made Simple version 2.2.4 or above." );
	script_xref( name: "URL", value: "https://github.com/bsmali4/cve/blob/master/CMS%20Made%20Simple%20Stored%20XSS.md" );
	script_xref( name: "URL", value: "https://github.com/bsmali4/cve/blob/master/CMS%20Made%20Simple%20UPLOAD%20FILE%20XSS.md" );
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
if(version_is_equal( version: version, test_version: "2.2.3.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

