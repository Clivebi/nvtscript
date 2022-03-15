CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114172" );
	script_version( "2020-12-08T08:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 08:52:45 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-01-03 10:08:21 +0100 (Fri, 03 Jan 2020)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-2166" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dovecot 2.0.x < 2.0.13 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to an authentication bypass vulnerability." );
	script_tag( name: "insight", value: "Script-login does not follow the user and group configuration
  settings, which might allow remote authenticated users to bypass intended access restrictions
  by leveraging a script." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dovecot versions 2.0.x before 2.0.13." );
	script_tag( name: "solution", value: "Update to version 2.0.13 or later." );
	script_xref( name: "URL", value: "https://dovecot.org/pipermail/dovecot/2011-May/059085.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_greater_equal( version: version, test_version: "2.0.0" ) && version_is_less( version: version, test_version: "2.0.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.13", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

