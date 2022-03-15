CPE = "cpe:/a:ibm:db2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812266" );
	script_version( "2020-04-17T03:30:22+0000" );
	script_tag( name: "last_modification", value: "2020-04-17 03:30:22 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-12-15 15:59:52 +0530 (Fri, 15 Dec 2017)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2014-4805" );
	script_bugtraq_id( 69541 );
	script_name( "IBM Db2 Information Disclosure Vulnerability Dec17" );
	script_tag( name: "summary", value: "IBM DB2 is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as during certain
  LOAD operations into Columnar Data Engine (CDE) tables, a temporary file
  containing user data may be created at the Db2 server. As the file only
  exists for the duration of the LOAD operation and is automatically removed
  on completion (both success and error), the vulnerability exists only temporarily." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to obtain sensitive information that may aid in further attacks." );
	script_tag( name: "affected", value: "IBM Db2 10.5 before FP4." );
	script_tag( name: "solution", value: "Apply the appropriate fix from reference link" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21681723" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_in_range( version: version, test_version: "10.5.0", test_version2: "10.5.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.5.0.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

