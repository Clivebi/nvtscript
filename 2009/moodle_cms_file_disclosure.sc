if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100085" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Moodle File Disclosure Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Moodle/Version" );
	script_tag( name: "summary", value: "An input filter for TeX formulas can be exploited to disclose files
  readable by the web server. This includes the moodle configuration
  file with all authentication data and server locations for directly
  connecting to backend database.
  TeX filter by default is off and in case of being activated mostly no
  complete LaTeX environment on a server system will be available." );
	script_tag( name: "affected", value: "Moodle 1.9.x (prior to 1.9.4),
  Moodle 1.8.x (prior to 1.8.8),
  Moodle 1.7.x (prior to 1.7.7)" );
	script_tag( name: "solution", value: "Several alternatives:

  1) deactivate TeX filter, if not needed

  2) use more restrictive mimetex program for rendering

  3) change LaTeX configuration (set 'openin_any=p' for paranoid!)

  or upgrade to latest development version where patch should be applied by now." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/502231/30/0/threaded" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
moodlePort = http_get_port( default: 80 );
if(!get_kb_item( NASLString( "www/", moodlePort, "/moodle" ) )){
	exit( 0 );
}
moodleVer = get_kb_item( "Moodle/Version" );
if(!moodleVer){
	exit( 0 );
}
if(version_in_range( version: moodleVer, test_version: "1.6", test_version2: "1.6.8" ) || version_in_range( version: moodleVer, test_version: "1.7", test_version2: "1.7.6" ) || version_in_range( version: moodleVer, test_version: "1.8", test_version2: "1.8.8" ) || version_in_range( version: moodleVer, test_version: "1.9", test_version2: "1.9.4" )){
	security_message( moodlePort );
}
exit( 0 );

