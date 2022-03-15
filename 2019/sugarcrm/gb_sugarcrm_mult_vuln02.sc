CPE = "cpe:/a:sugarcrm:sugarcrm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141817" );
	script_version( "$Revision: 12923 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-02 09:18:39 +0100 (Wed, 02 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-02 14:53:09 +0700 (Wed, 02 Jan 2019)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SugarCRM Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sugarcrm_detect.sc" );
	script_mandatory_keys( "sugarcrm/installed" );
	script_tag( name: "summary", value: "SugarCRM is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "SugarCRM is prone to multiple vulnerabilities:

  - Stored XSS vulnerability in a component of the Meetings module

  - Multiple Remote Code Execution vulnerabilities in a component of the Module Builder module

  - Remote Code Execution vulnerability in a component of the Web Logic Hooks module

  - Path Traversal vulnerability in a component of the Web Logic Hooks module" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "SugarCRM 7.9, 8.0 and 8.1." );
	script_tag( name: "solution", value: "Update to version 7.9.5, 8.0.2, 8.2.0 or later." );
	script_xref( name: "URL", value: "https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-006/" );
	script_xref( name: "URL", value: "https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-007/" );
	script_xref( name: "URL", value: "https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-008/" );
	script_xref( name: "URL", value: "https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-009/" );
	script_xref( name: "URL", value: "https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-010/" );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2018-05" );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2018-06" );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2018-07" );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2018-08" );
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
if(IsMatchRegexp( version, "^7\\.9\\." )){
	if(version_is_less( version: version, test_version: "7.9.5" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.9.5" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^8\\.0\\." )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^8\\.1\\." )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.2.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

