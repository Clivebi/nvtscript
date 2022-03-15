CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807815" );
	script_version( "2020-03-13T07:09:19+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 07:09:19 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-05-02 14:34:01 +0530 (Mon, 02 May 2016)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2016-0211", "CVE-2016-0215" );
	script_name( "IBM Db2 LUW Multiple Denial of Service Vulnerabilities - May16" );
	script_tag( name: "summary", value: "IBM Db2 is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error within application, while handling specially-crafted DRDA messages and
  specially-crafted SELECT statement with subquery containing the AVG OLAP function." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to terminate abnormally the application causing a denial of service condition." );
	script_tag( name: "affected", value: "IBM Db2 versions 9.7 through FP11, 10.1 through FP5 and 10.5 through FP7." );
	script_tag( name: "solution", value: "Apply the patches from the referenced advisories." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21979984" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21979986" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_in_range( version: version, test_version: "9.7.0.0", test_version2: "9.7.0.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.1.0.0", test_version2: "10.1.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.5.0.0", test_version2: "10.5.0.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

