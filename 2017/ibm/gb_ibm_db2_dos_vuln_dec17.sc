CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812264" );
	script_version( "2020-04-17T03:30:22+0000" );
	script_tag( name: "last_modification", value: "2020-04-17 03:30:22 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-12-15 15:19:39 +0530 (Fri, 15 Dec 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2014-6097" );
	script_bugtraq_id( 70983 );
	script_name( "IBM Db2 Denial of Service Vulnerability Dec17" );
	script_tag( name: "summary", value: "BM Db2 is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in handling 'ALTER TABLE' statement." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause the application to
  crash, resulting in denial-of-service conditions." );
	script_tag( name: "affected", value: "IBM Db2 versions 9.7 before FP10 and 9.8 through FP5." );
	script_tag( name: "solution", value: "Apply the appropriate fix from reference link" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21684812" );
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

