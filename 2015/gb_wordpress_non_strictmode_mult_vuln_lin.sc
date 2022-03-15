CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805988" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-3438" );
	script_bugtraq_id( 74269 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-12 14:01:19 +0530 (Mon, 12 Oct 2015)" );
	script_name( "WordPress 'Non-Strict Mode' Multiple Cross-Site Scripting Vulnerabilities (Linux)" );
	script_tag( name: "summary", value: "This host is running WordPress and is prone
  to multiple cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to improper input
  data sanitization via four-byte UTF-8 character or via an invalid character." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "WordPress versions before 4.1.2 on Linux." );
	script_tag( name: "solution", value: "Update to version 4.1.2 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://wordpress.org/news/2015/04/wordpress-4-1-2" );
	script_xref( name: "URL", value: "http://zoczus.blogspot.in/2015/04/plupload-same-origin-method-execution.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "os_detection.sc", "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!wpVer = get_app_version( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(version_is_less( version: wpVer, test_version: "4.1.2" )){
	report = "Installed Version: " + wpVer + "\n" + "Fixed Version:     " + "4.1.2" + "\n";
	security_message( data: report, port: wpPort );
	exit( 0 );
}

