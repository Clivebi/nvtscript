CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812268" );
	script_version( "2020-04-17T03:30:22+0000" );
	script_tag( name: "last_modification", value: "2020-04-17 03:30:22 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-12-15 15:44:32 +0530 (Fri, 15 Dec 2017)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2014-3094" );
	script_bugtraq_id( 69550 );
	script_name( "IBM Db2 Stack Buffer Overflow Vulnerability Dec17" );
	script_tag( name: "summary", value: "This host is running IBM Db2 and is prone to stack buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an improper bounds checking in the handling of the
  ALTER MODULE statement." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to execute arbitrary code with
  Db2 instance owner privileges. Failed attempts will likely cause a denial-of-service condition." );
	script_tag( name: "affected", value: "IBM Db2 9.7 through FP9a, 9.8 through FP5, 10.1 through FP4, and 10.5 before FP4." );
	script_tag( name: "solution", value: "Apply the appropriate fix from reference link" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21681631" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc" );
	script_mandatory_keys( "ibm/db2/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.5.0", test_version2: "10.5.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.5.0.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.1.0", test_version2: "10.1.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.1.0.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.7.0", test_version2: "9.7.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.7.0.10" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.8.0", test_version2: "9.8.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patch" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

