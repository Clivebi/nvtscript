CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813054" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2014-1665" );
	script_bugtraq_id( 65457 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-13 16:26:00 +0000 (Fri, 13 Apr 2018)" );
	script_tag( name: "creation_date", value: "2018-03-23 12:50:26 +0530 (Fri, 23 Mar 2018)" );
	script_name( "ownCloud XSS and CSRF Protection Bypass Vulnerabilities Mar18 - Linux" );
	script_tag( name: "summary", value: "ownCloud is prone to XSS and CSRF vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an insufficient
  validation of user supplied input for the 'filename' while uploading file." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to conduct an XSS attack when the victim tries to either view the
  contents of the file or delete the file. If the victim is an ownCloud
  administrator, an attacker can force the mounting of the webserver's local
  file system, leading to unauthorized access to server resources and potentially
  shell access." );
	script_tag( name: "affected", value: "ownCloud version 6.0.0a." );
	script_tag( name: "solution", value: "Update to version 6.0.1 or later.
  If upgrading is not an option, then the file can be removed by either
  1) manually removing the file from the disk via command line interface, or
  2) first renaming the file to something else and then deleting the file." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/31427" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/125086" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "owncloud/installed", "Host/runs_unixoide" );
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
if(vers == "6.0.0a"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.0.1 or later", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

