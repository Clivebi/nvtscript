CPE = "cpe:/a:dotcms:dotcms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106365" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-02 09:37:45 +0700 (Wed, 02 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-4040" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "dotCMS SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotcms_detect.sc" );
	script_mandatory_keys( "dotCMS/installed" );
	script_tag( name: "summary", value: "dotCMS is prone to a SQL injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SQL injection vulnerability in the 'Workflow Screen' allows remote
administrators to execute arbitrary SQL commands via the _EXT_15_orderby parameter." );
	script_tag( name: "impact", value: "An authenticated attacker may execute arbitrary SQL commands." );
	script_tag( name: "affected", value: "dotCMS before 3.3.2" );
	script_tag( name: "solution", value: "Update to dotCMS 3.3.2 or later." );
	script_xref( name: "URL", value: "https://security.elarlang.eu/multiple-sql-injection-vulnerabilities-in-dotcms-8x-cve-full-disclosure.html" );
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
if(version_is_less( version: version, test_version: "3.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

