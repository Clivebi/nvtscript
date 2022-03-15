CPE = "cpe:/a:moodle:moodle";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800767" );
	script_version( "2020-12-08T08:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 08:52:45 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)" );
	script_cve_id( "CVE-2010-1613", "CVE-2010-1616" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Moodle Session Fixation Vulnerability" );
	script_xref( name: "URL", value: "http://moodle.org/security/" );
	script_xref( name: "URL", value: "http://tracker.moodle.org/browse/MDL-17207" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "affected", value: "Moodle version 1.8.12 and prior, version 1.9.x prior to 1.9.8." );
	script_tag( name: "insight", value: "The flaws are exists due to:

  - failure to enable 'Regenerate session id during login', which can be
  exploited to conduct session fixation attacks

  - creating new roles when restoring a course, which allows teachers to create
  new accounts if they do not have the 'moodle/user:create' capability" );
	script_tag( name: "solution", value: "Update to 1.9.8 or later." );
	script_tag( name: "summary", value: "Moodle is prone to a session fixation vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct session
  fixation attacks." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "1.8", test_version2: "1.8.12" ) || version_in_range( version: version, test_version: "1.9", test_version2: "1.9.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.9.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

