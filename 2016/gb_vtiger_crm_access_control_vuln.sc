CPE = "cpe:/a:vtiger:vtiger_crm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106148" );
	script_version( "$Revision: 12926 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-03 04:38:48 +0100 (Thu, 03 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-21 09:24:27 +0700 (Thu, 21 Jul 2016)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_cve_id( "CVE-2016-4834" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Vtiger CRM Access Control Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vtiger_crm_detect.sc" );
	script_mandatory_keys( "vtiger/detected" );
	script_tag( name: "summary", value: "Vtiger CRM is prone to an access control vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Vtiger CRM contains a vulnerability where it does not properly restrict
access to user information data." );
	script_tag( name: "impact", value: "A user with user privileges may create new users or alter existing user
information." );
	script_tag( name: "affected", value: "Vtiger CRM 6.4.0 and earlier" );
	script_tag( name: "solution", value: "Upgrade to Version 6.5.0 or later" );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN01956993/" );
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
if(version_is_less( version: version, test_version: "6.5.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.5.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

