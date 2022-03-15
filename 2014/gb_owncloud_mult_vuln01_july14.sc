CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804658" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_cve_id( "CVE-2012-5056", "CVE-2012-5057", "CVE-2012-5336" );
	script_bugtraq_id( 68295, 68305 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-07-03 12:50:12 +0530 (Thu, 03 Jul 2014)" );
	script_name( "ownCloud Multiple Vulnerabilities-01 July14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an:

  - Input passed to 'apps/files_odfviewer/src/webodf/webodf/flashput/PUT.swf'
  script via 'readyCallback' parameter is not sanitized before returning it to
  users.

  - Input passed to 'lib/db.php' script via malformed query is not sanitized
  before returning it to users.

  - Input passed to 'apps/gallery/templates/index.php' script via 'root'
  parameter is not sanitized before returning it to users.

  - Application does not validate the URL path upon submission to the 'index.php'
  script.

  - Improper validation of input passed to 'lib/base.php' script via
  'user_id session' variable." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain access to
arbitrary user files, insert arbitrary HTTP headers and execute arbitrary
script code in a user's browser session within the trust relationship
between their browser and the server." );
	script_tag( name: "affected", value: "ownCloud Server 4.0.x before 4.0.8" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.0.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/CVE-2012-5336" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/CVE-2012-5057" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/CVE-2012-5056" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ownPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ownVer = get_app_version( cpe: CPE, port: ownPort )){
	exit( 0 );
}
if(version_in_range( version: ownVer, test_version: "4.0.0", test_version2: "4.0.7" )){
	report = report_fixed_ver( installed_version: ownVer, vulnerable_range: "4.0.0 - 4.0.7" );
	security_message( port: ownPort, data: report );
	exit( 0 );
}

