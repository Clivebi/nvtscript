CPE = "cpe:/a:theforeman:foreman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106421" );
	script_version( "$Revision: 12313 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-4475" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Foreman Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foreman_detect.sc" );
	script_mandatory_keys( "foreman/installed" );
	script_tag( name: "summary", value: "Foreman is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When accessing Foreman as a user limited to specific organization or
location, these are not taken into account in the API or parts of the UI. This allows a user to view, edit and
delete organizations and locations they are not associated with if they have the requisite permissions." );
	script_tag( name: "affected", value: "Version 1.1.0 to 1.11.3" );
	script_tag( name: "solution", value: "Upgrade to 1.11.4 or later." );
	script_xref( name: "URL", value: "https://theforeman.org/security.html#2016-4475" );
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
if(version_in_range( version: version, test_version: "1.1.0", test_version2: "1.11.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.11.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

