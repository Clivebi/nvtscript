CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809474" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2016-4436" );
	script_bugtraq_id( 91280 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-18 11:00:43 +0530 (Fri, 18 Nov 2016)" );
	script_name( "Apache Struts Security Update (S2-035)" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-035" );
	script_xref( name: "Advisory-ID", value: "S2-035" );
	script_tag( name: "summary", value: "Apache Struts is prone to an unspecified
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The flaw exists due to the method used to clean up
  action name can produce vulnerable payload based on crafted input." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass
  certain security restrictions and perform unauthorized actions. This may lead to further
  attacks." );
	script_tag( name: "affected", value: "Apache Struts 2.x through 2.3.28.1 and 2.5.0." );
	script_tag( name: "solution", value: "Update to version 2.3.29, 2.5.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if( version_in_range( version: vers, test_version: "2.0.0", test_version2: "2.3.28.1" ) ){
	fix = "2.3.29";
	VULN = TRUE;
}
else {
	if(version_is_equal( version: vers, test_version: "2.5" )){
		fix = "2.5.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

