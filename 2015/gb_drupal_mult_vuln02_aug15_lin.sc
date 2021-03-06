CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805967" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-6665", "CVE-2015-6659" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-28 12:40:50 +0530 (Fri, 28 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal Multiple Vulnerabilities-02 August15 (Linux)" );
	script_tag( name: "summary", value: "This host is running Drupal and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exixts as,

  - An error in the Ajax handler involving a whitelisted HTML element, possibly
  related to the 'a' tag.

  - An error in the SQL comment filtering system in the Database API." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data, and
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "Drupal 7.x before 7.39 on Linux." );
	script_tag( name: "solution", value: "Upgrade to version 7.39 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2015-003" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!drupalPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!drupalVer = get_app_version( cpe: CPE, port: drupalPort, version_regex: "^[0-9]\\.[0-9]+" )){
	exit( 0 );
}
if(IsMatchRegexp( drupalVer, "^7" )){
	if(version_in_range( version: drupalVer, test_version: "7.0", test_version2: "7.38" )){
		report = "Installed version: " + drupalVer + "\n" + "Fixed version:     " + "7.39" + "\n";
		security_message( data: report, port: drupalPort );
		exit( 0 );
	}
}

