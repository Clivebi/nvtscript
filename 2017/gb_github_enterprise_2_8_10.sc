CPE = "cpe:/a:github:github_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140227" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 12106 $" );
	script_name( "GitHub Enterprise Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://enterprise.github.com/releases/series/2.8" );
	script_tag( name: "summary", value: "Multiple vulnerabilities where fixed with the 2.8.10 release.
HIGH: Improper sanitization of user markup content, while not allowing full XSS, could have been abused to leak sensitive data or perform actions as the user viewing the content.
LOW: Detect and reject any Git content that shows evidence of being part of a SHA-1 collision attack." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to GitHub Enterprise 2.8.10" );
	script_tag( name: "affected", value: "GitHub Enterprise < 2.8.10" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-03-30 14:14:15 +0200 (Thu, 30 Mar 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_github_enterprise_version.sc" );
	script_mandatory_keys( "github/enterprise/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.8.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.8.10" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

