CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802456" );
	script_version( "2020-03-12T10:08:50+0000" );
	script_tag( name: "last_modification", value: "2020-03-12 10:08:50 +0000 (Thu, 12 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-09-06 16:20:17 +0530 (Thu, 06 Sep 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-2180" );
	script_bugtraq_id( 53873 );
	script_name( "IBM Db2 Chaining Functionality DRDA Module DoS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49437/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75418" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1IC82234" );
	script_xref( name: "URL", value: "http://www-304.ibm.com/support/docview.wss?uid=swg21597090" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg27007053" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc" );
	script_mandatory_keys( "ibm/db2/detected" );
	script_tag( name: "impact", value: "Successful exploitation allows remote users to cause denial of service." );
	script_tag( name: "affected", value: "IBM Db2 version 9.7 before FP6 and IBM Db2 version 9.8 before FP5." );
	script_tag( name: "insight", value: "The flaw is caused due an error within chaining functionality in the
  Distributed Relational Database Architecture (DRDA) module, which can be
  exploited to cause a crash by sending a specially crafted DRDA request." );
	script_tag( name: "solution", value: "Upgrade to IBM Db2 version 9.7 FP6, 9.8 FP5 or later." );
	script_tag( name: "summary", value: "IBM Db2 is prone to a denial of service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.7.0.0", test_version2: "9.7.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.7.0.6" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.8.0.0", test_version2: "9.8.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.8.0.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

