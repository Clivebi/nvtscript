CPE = "cpe:/a:wordpress:wordpress_mu";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800376" );
	script_version( "$Revision: 14012 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 10:13:44 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1030" );
	script_bugtraq_id( 34075 );
	script_name( "WordPress MU Cross-Site Scripting Vulnerability - Apr09" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8196" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49184" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Mar/1021838.html" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute malicious crafted
  HTTP headers and conduct cross site scripting attacks to gain administrative
  privileges into the affected web application." );
	script_tag( name: "affected", value: "WordPress MU before 2.7 on all running platform." );
	script_tag( name: "insight", value: "The vulnerability is due to improper validation of user supplied input in
  'wp-includes/wpmu-functions.php' for choose_primary_blog function." );
	script_tag( name: "solution", value: "Update to Version 2.7 or later." );
	script_tag( name: "summary", value: "The host is running WordPress MU and is prone to Cross-Site
  Scripting Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wpmuPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: wpmuPort )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "2.7" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.7" );
	security_message( port: wpmuPort, data: report );
	exit( 0 );
}
exit( 99 );

