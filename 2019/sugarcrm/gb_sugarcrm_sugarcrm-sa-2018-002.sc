CPE = "cpe:/a:sugarcrm:sugarcrm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141816" );
	script_version( "$Revision: 12959 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-07 12:13:35 +0100 (Mon, 07 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-02 14:46:41 +0700 (Wed, 02 Jan 2019)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SugarCRM < 7.9.4.0 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sugarcrm_detect.sc" );
	script_mandatory_keys( "sugarcrm/installed" );
	script_tag( name: "summary", value: "SugarCRM is prone to a privilege escalation vulnerability." );
	script_tag( name: "insight", value: "When LDAP authentication is enabled, the username input is not properly
escaped when constructing the LDAP bind filter. Depending on your LDAP configuration and setup this may result in
privilege escalation. This fix addresses the usage of proper username escaping when creating the LDAP bind and
LDAP filters." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "SugarCRM 7.9." );
	script_tag( name: "solution", value: "Update to version 7.9.4.0 or later." );
	script_xref( name: "URL", value: "https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2018-002/" );
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
	if(version_is_less( version: version, test_version: "7.9.4.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.9.4.0" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

