CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803756" );
	script_version( "2020-03-13T07:09:19+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 07:09:19 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2013-09-05 15:09:14 +0530 (Thu, 05 Sep 2013)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2013-3475" );
	script_bugtraq_id( 60255 );
	script_name( "IBM Db2 Audit Facility Local Privilege Escalation Vulnerability (Linux)" );
	script_tag( name: "summary", value: "IBM Db2 is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the appropriate fix" );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within the setuid-set db2aud binary, which
  can be exploited to cause a stack-based buffer overflow." );
	script_tag( name: "affected", value: "IBM Db2 version 9.1.x, 9.5.x before FP9, 9.7.x before FP7, 9.8.x before FP5
  and 10.1.x before FP1 on Linux." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain escalated privileges and
  cause a stack-based buffer overflow." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52663" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/84358" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21639355" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ibm/db2/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^9\\.1\\." )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.5.0.0", test_version2: "9.5.0.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.5.0.9" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.7.0.0", test_version2: "9.7.0.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.7.0.7" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.8.0.0", test_version2: "9.8.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.8.0.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "10.1.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.1.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

