CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142029" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-22 13:59:06 +0700 (Fri, 22 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-25 12:57:00 +0000 (Thu, 25 Apr 2019)" );
	script_cve_id( "CVE-2019-8942" );
	script_bugtraq_id( 107088 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WordPress RCE Vulnerability CVE-2019-8942 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "WordPress allows remote code execution because an _wp_attached_file Post Meta
entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with
author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif
metadata. Exploitation can leverage CVE-2019-8943." );
	script_tag( name: "affected", value: "WordPress prior version 4.9.9 and 5.0.1." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 4.9.9, 5.0.1 or later." );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/" );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "4.9.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.9", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^5\\." )){
	if(version_is_less( version: version, test_version: "5.0.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "5.0.1", install_path: path );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

