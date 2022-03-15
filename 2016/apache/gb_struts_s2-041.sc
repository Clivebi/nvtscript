CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808537" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2016-4465" );
	script_bugtraq_id( 91278 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-18 14:36:30 +0530 (Fri, 18 Nov 2016)" );
	script_name( "Apache Struts Security Update (S2-041)" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-041" );
	script_xref( name: "Advisory-ID", value: "S2-041" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-058" );
	script_xref( name: "Advisory-ID", value: "S2-058" );
	script_tag( name: "summary", value: "Apache Struts is prone to a Denial of Service (DoS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "If an application allows enter an URL field in a form
  and built-in URLValidator is used, it is possible to prepare a special URL which will be
  used to overload server process when performing validation of the URL." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to
  cause a DoS." );
	script_tag( name: "affected", value: "Apache Struts 2.3.20 through 2.3.28.1 and 2.5 through
  2.5.12." );
	script_tag( name: "solution", value: "Update to version 2.3.29, 2.5.13 or later." );
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
if( version_in_range( version: vers, test_version: "2.5.0", test_version2: "2.5.12" ) ){
	fix = "2.5.13";
	VULN = TRUE;
}
else {
	if(version_in_range( version: vers, test_version: "2.3.20", test_version2: "2.3.28.1" )){
		fix = "2.3.29";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

