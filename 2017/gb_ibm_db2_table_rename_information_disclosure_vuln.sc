CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810704" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-09 15:35:12 +0530 (Thu, 09 Mar 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-1150" );
	script_bugtraq_id( 96597 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Db2 Table Rename Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running IBM Db2 and is prone to information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when a table is renamed and a new table is created with the
  old name, users who had access on the old table may be able to access the new table." );
	script_tag( name: "impact", value: "Successful exploitation will allow an authenticated attacker with specialized
  access to tables that they should not be permitted to view." );
	script_tag( name: "affected", value: "IBM Db2 versions 11.1, 10.1 and 10.5." );
	script_tag( name: "solution", value: "Update to version 10.1 Fix Pack 6, 10.5 Fix Pack 9, 11.1.1 with Interim Fix
  IT19400 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc" );
	script_mandatory_keys( "ibm/db2/detected" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21999515" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.1.0", test_version2: "10.1.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.1.0.6" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.5.0", test_version2: "10.5.0.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.5.0.9" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "11.1.0", test_version2: "11.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply Interim Fix IT19400" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

