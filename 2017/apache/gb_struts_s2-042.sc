CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811797" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2016-6795" );
	script_bugtraq_id( 93773 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)" );
	script_tag( name: "creation_date", value: "2017-09-28 12:14:12 +0530 (Thu, 28 Sep 2017)" );
	script_name( "Apache Struts Security Update (S2-042)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-042" );
	script_xref( name: "Advisory-ID", value: "S2-042" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-058" );
	script_xref( name: "Advisory-ID", value: "S2-058" );
	script_tag( name: "summary", value: "Apache Struts is prone to a path traversal
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "It is possible to prepare a special URL which will be
  used for path traversal and execution of arbitrary code on server side." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to perform
  a path traversal attack, which could allow the attacker to execute arbitrary code on the
  targeted server." );
	script_tag( name: "affected", value: "Apache Struts 2.3.1 through 2.3.30 and 2.5 through
  2.5.2." );
	script_tag( name: "solution", value: "Update to version 2.3.31, 2.5.5 or later." );
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
path = infos["location"];
if( version_in_range( version: vers, test_version: "2.3.1", test_version2: "2.3.30" ) ){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.31", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: vers, test_version: "2.5.0", test_version2: "2.5.2" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.5.5", install_path: path );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

