CPE = "cpe:/a:horde:horde_groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140527" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-22 17:09:33 +0700 (Wed, 22 Nov 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-29 22:15:00 +0000 (Sat, 29 Aug 2020)" );
	script_cve_id( "CVE-2017-16906", "CVE-2017-16907", "CVE-2017-16908", "CVE-2017-17781" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Horde Groupware Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "horde_detect.sc" );
	script_mandatory_keys( "horde/installed" );
	script_tag( name: "summary", value: "Horde Groupware is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Horde Groupware is prone to multiple vulnerabilities:

  - Multiple cross-site scripting vulnerabilities in the URL field in a 'Calendar -> New Event' action, the Color
field in a Create Task List action and the Name field during creation of a new Resource. (CVE-2017-16906,
CVE-2017-16907, CVE-2017-16906)

  - SQL Injection exists via the group parameter to /services/prefs.php or the homePostalCode parameter to
/turba/search.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://code610.blogspot.com/2017/11/rce-via-xss-horde-5219.html" );
	script_xref( name: "URL", value: "https://code610.blogspot.com/2017/12/modus-operandi-horde-52x.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "5.2.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

