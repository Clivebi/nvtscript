CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807972" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2016-3081", "CVE-2016-3087" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:32:08 +0530 (Fri, 06 May 2016)" );
	script_name( "Apache Struts Security Update (S2-032, S2-033) - Version Check" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-033" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-032" );
	script_xref( name: "Advisory-ID", value: "S2-033" );
	script_xref( name: "Advisory-ID", value: "S2-032" );
	script_tag( name: "summary", value: "Apache Struts is prone to multiple arbitrary code
  execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - An error occurs in prefix method when Dynamic Method Invocation is enabled.

  - An error occurs in REST Plugin with ! when Dynamic Method Invocation is enabled." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to
  execute arbitrary code." );
	script_tag( name: "affected", value: "Apache Struts 2.3.20 through 2.3.28 except 2.3.20.3
  and 2.3.24.3." );
	script_tag( name: "solution", value: "Update to version 2.3.20.3, 2.3.24.3, 2.3.28.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(version_is_equal( version: vers, test_version: "2.3.20.3" ) || version_is_equal( version: vers, test_version: "2.3.24.3" )){
	exit( 99 );
}
if(version_in_range( version: vers, test_version: "2.3.20", test_version2: "2.3.28" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.28.1, 2.3.20.3, 2.3.24.3", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

