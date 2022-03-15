CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802463" );
	script_version( "2020-03-12T10:08:50+0000" );
	script_tag( name: "last_modification", value: "2020-03-12 10:08:50 +0000 (Thu, 12 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-09-27 15:12:59 +0530 (Thu, 27 Sep 2012)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-3324" );
	script_name( "IBM Db2 UTL_FILE Module Directory Traversal Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/77924" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1IC85513" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21611040" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ibm/db2/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation allows remote users to modify, delete or read
  arbitrary files via a pathname in the file field." );
	script_tag( name: "affected", value: "IBM Db2 version 10.1 before FP1 on Windows" );
	script_tag( name: "insight", value: "The flaw is caused due an improper validation of user-supplied input by
  routines within the UTL_FILE module. Which allows attackers to read arbitrary files." );
	script_tag( name: "solution", value: "Upgrade to IBM Db2 version 10.1 FP1 or later." );
	script_tag( name: "summary", value: "IBM Db2 is prone to a directory traversal vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "10.1.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.1.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

