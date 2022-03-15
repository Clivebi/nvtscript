if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800702" );
	script_version( "2020-03-13T10:05:38+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:05:38 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-1239" );
	script_bugtraq_id( 34650 );
	script_name( "IBM Db2 Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49864" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0912" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21381257" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ibm/db2/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker gain sensitive information of
  the affected remote system." );
	script_tag( name: "affected", value: "IBM Db2 versions 9.1 before 9.1 FP7." );
	script_tag( name: "insight", value: "This flaw is due to the 'INNER JOIN' and 'OUTER JOIN' predicate which allows
  remote attackers to execute arbitrary queries." );
	script_tag( name: "summary", value: "IBM Db2 is prone to an information disclosure vulnerability." );
	script_tag( name: "solution", value: "Apply the referenced vendor security update." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:ibm:db2";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "9.1.0.0", test_version2: "9.1.0.6a" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.0.7" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

