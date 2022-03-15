CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808021" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2016-4003", "CVE-2016-2162", "CVE-2016-3093" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-06 11:03:24 +0530 (Mon, 06 Jun 2016)" );
	script_name( "Apache Struts Security Update (S2-028, S2-030, S2-034)" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-028" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-030" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-034" );
	script_xref( name: "Advisory-ID", value: "S2-028" );
	script_xref( name: "Advisory-ID", value: "S2-030" );
	script_xref( name: "Advisory-ID", value: "S2-034" );
	script_tag( name: "summary", value: "Apache Struts is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - The Apache Struts frameworks when forced, performs double evaluation of attributes'
  values assigned to certain tags so it is possible to pass in a value that will be
  evaluated again when a tag's attributes will be rendered.

  - The interceptor doesn't perform any validation of the user input and accept arbitrary
  string which can be used by a developer to display language selected by the user.

  - The application does not properly validate cache method references when used with OGNL
  before 3.0.12." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to
  inject arbitrary web script or HTML via multi-byte characters in a url-encoded parameter
  or a denial of service (block access to a web site) via unspecified vectors." );
	script_tag( name: "affected", value: "Apache Struts 2.x through 2.3.24.1." );
	script_tag( name: "solution", value: "Update to version 2.3.28 or later." );
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
if(version_in_range( version: vers, test_version: "2.0.0", test_version2: "2.3.24.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.28", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

