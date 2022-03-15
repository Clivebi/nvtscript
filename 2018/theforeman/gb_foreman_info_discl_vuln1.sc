CPE = "cpe:/a:theforeman:foreman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141465" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-11 10:23:21 +0700 (Tue, 11 Sep 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2016-7078" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Foreman < 1.15.0 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foreman_detect.sc" );
	script_mandatory_keys( "foreman/installed" );
	script_tag( name: "summary", value: "Foreman is vulnerable to an information leak through organizations and
locations feature. When a user is assigned _no_ organizations/locations, they are able to view all resources
instead of none (mirroring an administrator's view). The user's actions are still limited by their assigned
permissions, e.g. to control viewing, editing and deletion." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Foreman prior to version 1.15.0." );
	script_tag( name: "solution", value: "Update to version 1.15.0 or later." );
	script_xref( name: "URL", value: "https://projects.theforeman.org/issues/16982" );
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
if(version_is_less( version: version, test_version: "1.15.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.15.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

