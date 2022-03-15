CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901081" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-4332" );
	script_bugtraq_id( 37332 );
	script_name( "IBM Db2 db2pd Denial Of Service Vulnerability (Linux)" );
	script_xref( name: "URL", value: "ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v95/APARLIST.TXT" );
	script_xref( name: "URL", value: "ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v91/APARLIST.TXT" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ibm/db2/detected", "Host/runs_unixoide" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of service
  (null pointer dereference and application crash)." );
	script_tag( name: "affected", value: "IBM DB2 version 9.1 prior to FP7 and 9.5 prior to FP5." );
	script_tag( name: "insight", value: "The flaw is due to null pointer dereference error in db2pd within
  the problem determination component via unspecified vectors." );
	script_tag( name: "solution", value: "Update IBM Db2 9.1 FP7, 9.5 FP5 or later." );
	script_tag( name: "summary", value: "IBM Db2 is prone to a denial of service vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.1.0.0", test_version2: "9.1.0.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.0.7" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.5.0.0", test_version2: "9.5.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.5.0.5" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

