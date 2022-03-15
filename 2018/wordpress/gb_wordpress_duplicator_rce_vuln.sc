CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141688" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-15 11:56:56 +0700 (Thu, 15 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-10 14:58:00 +0000 (Mon, 10 Dec 2018)" );
	script_cve_id( "CVE-2018-17207" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress Duplicator Plugin < 1.2.42 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "An issue was discovered in Snap Creek Duplicator. By accessing leftover
installer files (installer.php and installer-backup.php), an attacker can inject PHP code into wp-config.php
during the database setup step, achieving arbitrary code execution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Snap Creek Duplicator plugin prior to version 1.2.42." );
	script_tag( name: "solution", value: "Update to version 1.2.42 or later and remove the leftover files." );
	script_xref( name: "URL", value: "https://www.synacktiv.com/ressources/advisories/WordPress_Duplicator-1.2.40-RCE.pdf" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
urls = make_list( "/installer.php",
	 "/installer-backup.php" );
for file in urls {
	url = dir + file;
	res = http_get_cache( port: port, item: url );
	if(ContainsString( res, "<title>Duplicator</title>" ) && ContainsString( res, "<label>Plugin Version:</label>" )){
		vers = eregmatch( pattern: "<td class=\"dupx-header-version\">[^v]+version: ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			if(version_is_less( version: vers[1], test_version: "1.2.42" )){
				report = report_fixed_ver( installed_version: vers[1], fixed_version: "1.2.42" );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

