CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804364" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-7344", "CVE-2013-0303" );
	script_bugtraq_id( 58109 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-07 10:17:33 +0530 (Mon, 07 Apr 2014)" );
	script_name( "ownCloud PHP Remote Code Execution Vulnerabilities Apr14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to remote code execution
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Unspecified input passed to core/ajax/translations.php is not properly
  sanitized before being used.

  - Unspecified input passed to core/settings.php is not properly sanitized
  before being used." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to mount the local
filesystem and gain access to the information contained within it." );
	script_tag( name: "affected", value: "ownCloud Server version 4.5.x before 4.5.6 and 4.0.x before 4.0.12" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.5.6 or 4.0.12 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52303" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q1/378" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2013-006" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: ownVer, test_version: "4.5.0", test_version2: "4.5.5" ) || version_in_range( version: ownVer, test_version: "4.0.0", test_version2: "4.0.11" )){
	security_message( port: ownPort );
	exit( 0 );
}

