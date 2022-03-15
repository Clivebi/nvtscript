CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804276" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-0307", "CVE-2013-0299", "CVE-2013-0297" );
	script_bugtraq_id( 58107, 58484, 58485 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-05-05 10:31:11 +0530 (Mon, 05 May 2014)" );
	script_name( "ownCloud Multiple XSS & CSRF Vulnerabilities -01 May14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to multiple cross-site
scripting and cross-site request forgery vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Improper validation of user-supplied input passed via 'site_name' and
'site_url' parameters to /apps/external/ajax/setsites.php script, 'Group Input'
parameter passed to the settings.php script.

  - Insufficient validation of user-supplied input passed via the 'lat' and
'lng' parameters to apps/calendar/ajax/settings/guesstimezone.php, the
'timezonedetection' parameter to calendar/ajax/settings/timezonedetection.php,
admin_export parameter to apps/admin_migrate/settings.php, operation parameter to
apps/user_migrate/ajax/export.php, unspecified vectors to
apps/user_ldap/settings.php" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct request forgery
attacks and execute arbitrary script code in a user's browser." );
	script_tag( name: "affected", value: "ownCloud Server before version 4.0.12 and 4.5.x before 4.5.7" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.0.12 or 4.5.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q1/378" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2013-004" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2013-003" );
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
if(version_is_less( version: ownVer, test_version: "4.0.12" ) || version_in_range( version: ownVer, test_version: "4.5.0", test_version2: "4.5.6" )){
	security_message( port: ownPort );
	exit( 0 );
}

