CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800704" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-6767", "CVE-2008-6762" );
	script_name( "WordPress Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2008-12/0226.html" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to causes denial of service or to redirect
  the URL to any malicious website and conduct phishing attacks." );
	script_tag( name: "affected", value: "WordPress version 2.6.x up to 2.6.3." );
	script_tag( name: "insight", value: "Multiple flaws are due to lack of sanitization in user supplied data which
  can be exploited through 'wp-admin/upgrade.php' via a direct request and
  'wp-admin/upgrade.php' via a URL in the backto parameter." );
	script_tag( name: "solution", value: "Update to version 2.7.1 or later." );
	script_tag( name: "summary", value: "This host has WordPress installed and is prone to Multiple
  Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.6", test_version2: "2.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

