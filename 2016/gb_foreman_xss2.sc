CPE = "cpe:/a:theforeman:foreman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106417" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2016-6320" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Foreman XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foreman_detect.sc" );
	script_mandatory_keys( "foreman/installed" );
	script_tag( name: "summary", value: "Foreman is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Network interface identifiers stored for hosts may contain HTML or
JavaScript that allows a stored XSS vulnerability when later viewing the host edit form." );
	script_tag( name: "affected", value: "Version 1.8.0 to 1.12.1." );
	script_tag( name: "solution", value: "Upgrade to 1.12.2 or later." );
	script_xref( name: "URL", value: "https://theforeman.org/security.html#2016-6320" );
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
if(version_in_range( version: version, test_version: "1.8.0", test_version2: "1.12.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

