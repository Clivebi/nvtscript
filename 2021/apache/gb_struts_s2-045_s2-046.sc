CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117286" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2017-5638" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-06 10:40:01 +0000 (Tue, 06 Apr 2021)" );
	script_name( "Apache Struts Security Update (S2-045, S2-046) - Version Check" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-045" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-046" );
	script_xref( name: "Advisory-ID", value: "S2-045" );
	script_xref( name: "Advisory-ID", value: "S2-046" );
	script_tag( name: "summary", value: "Apache Struts is prone to multiple remote code
  execution (RCE) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The following different vector for the same
  vulnerability (tracked as CVE-2017-5638) exists:

  - S2-045: It is possible to perform a RCE attack with a malicious Content-Type value. If
  the Content-Type value isn't valid an exception is thrown which is then used to display
  an error message to a user.

  - S2-046: It is possible to perform a RCE attack with a malicious Content-Disposition
  value or with improper Content-Length header. If the Content-Disposition /
  Content-Length value is not valid an exception is thrown which is then used to display
  an error message to a user." );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an
  attacker to execute arbitrary code in the context of the affected application." );
	script_tag( name: "affected", value: "Apache Struts 2.3.5 through 2.3.31 and 2.5.x through
  2.5.10." );
	script_tag( name: "solution", value: "Update to version 2.3.32, 2.5.10.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: version, test_version: "2.3.5", test_version2: "2.3.31" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.32", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.5.0", test_version2: "2.5.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5.10.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

