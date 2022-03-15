CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812692" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-6389" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-01 19:07:00 +0000 (Fri, 01 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-02-05 20:13:56 +0530 (Mon, 05 Feb 2018)" );
	script_name( "WordPress 'load-scripts.php' DoS Vulnerability - Windows" );
	script_tag( name: "summary", value: "WordPress is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the file 'load-scripts.php'
  do not require any authentication and file selectively calls required JavaScript
  files by passing their names into the 'load' parameter, separated by a comma." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct a denial of service condition on affected system." );
	script_tag( name: "affected", value: "WordPress versions 4.9.2 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://thehackernews.com/2018/02/wordpress-dos-exploit.html" );
	script_xref( name: "URL", value: "https://baraktawily.blogspot.in/2018/02/how-to-dos-29-of-world-wide-websites.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "os_detection.sc", "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "4.9.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "NoneAvailable", install_path: path );
	security_message( data: report, port: path );
	exit( 0 );
}
exit( 99 );

