CPE = "cpe:/a:modx:revolution";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106459" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-09 11:42:44 +0700 (Fri, 09 Dec 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-10037", "CVE-2016-10038", "CVE-2016-10039" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MODX CMS Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_modx_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "modx_cms/installed" );
	script_tag( name: "summary", value: "MODX Revolution CMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "MODX Revolution CMS is prone to multiple vulnerabilities:

  - Critical settings visible in MODx.config

  - Local file inclusion/traversal/manipulation

  - Unauthenticated access to processors

  - Path traversal in modConnectorResponse action param" );
	script_tag( name: "impact", value: "An attacker access or manipulate files on the system." );
	script_tag( name: "affected", value: "Version 2.5.1 and prior." );
	script_tag( name: "solution", value: "Update to version 2.5.2" );
	script_xref( name: "URL", value: "https://raw.githubusercontent.com/modxcms/revolution/v2.5.2-pl/core/docs/changelog.txt" );
	script_xref( name: "URL", value: "https://github.com/modxcms/revolution/pull/13170" );
	script_xref( name: "URL", value: "https://github.com/modxcms/revolution/pull/13176" );
	script_xref( name: "URL", value: "https://github.com/modxcms/revolution/pull/13175" );
	script_xref( name: "URL", value: "https://github.com/modxcms/revolution/pull/13173" );
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
if(version_is_less( version: version, test_version: "2.5.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

