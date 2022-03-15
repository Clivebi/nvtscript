if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801002" );
	script_version( "2020-03-13T10:05:38+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:05:38 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3473" );
	script_name( "IBM Db2 Unspecified Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_ibm_db2_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ibm/db2/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21403619" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21386689" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053" );
	script_tag( name: "affected", value: "IBM Db2 version 9.1 prior to Fixpak 8." );
	script_tag( name: "insight", value: "An unspecified error in the handling of 'SET SESSION AUTHORIZATION'
  statements that can be exploited to execute the statement without having the required privileges." );
	script_tag( name: "solution", value: "Update Db2 9.1 Fixpak 8 or later." );
	script_tag( name: "summary", value: "IBM Db2 is prone to an unspecified vulnerability." );
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
if(version_in_range( version: version, test_version: "9.1.0.0", test_version2: "9.1.800.1022" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.800.1023" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

