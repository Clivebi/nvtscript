CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144400" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-08-17 02:36:58 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_cve_id( "CVE-2019-0230", "CVE-2019-0233" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Struts Security Update (S2-059, S2-060)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_tag( name: "summary", value: "Apache Struts is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2019-0230: Forced double OGNL evaluation, when evaluated on raw user input in tag
  attributes, may lead to remote code execution.

  - CVE-2019-0233: Access permission override causing a denial of service when performing
  a file upload." );
	script_tag( name: "affected", value: "Apache Struts 2.0.0 through 2.5.20." );
	script_tag( name: "solution", value: "Update to version 2.5.22 or later." );
	script_xref( name: "URL", value: "https://struts.apache.org/announce.html#a20200813" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-059" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-060" );
	script_xref( name: "Advisory-ID", value: "S2-059" );
	script_xref( name: "Advisory-ID", value: "S2-060" );
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
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "2.0.0", test_version2: "2.5.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5.22", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

