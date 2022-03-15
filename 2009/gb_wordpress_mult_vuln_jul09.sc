CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800657" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-2432", "CVE-2009-2431", "CVE-2009-2336", "CVE-2009-2335", "CVE-2009-2334" );
	script_bugtraq_id( 35581, 35584 );
	script_name( "WordPress Multiple Vulnerabilities - July09" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1833" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Jul/1022528.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/504795/100/0/threaded" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to view the content of plugins
  configuration pages, inject malicious scripting code, or gain knowledge of sensitive username information." );
	script_tag( name: "affected", value: "WordPress version prior to 2.8.1 on all running platform." );
	script_tag( name: "insight", value: "- Error in 'wp-settings.php' which may disclose the sensitive information via
  a direct request.

  - username of a post's author is placed in an HTML comment, which allows
  remote attackers to obtain sensitive information by reading the HTML source.

  - Error occur when user attempt for failed login or password request depending
  on whether the user account exists, and it can be exploited by enumerate valid usernames.

  - wp-admin/admin.php does not require administrative authentication
  to access the configuration of a plugin, which allows attackers to specify a
  configuration file in the page parameter via collapsing-archives/options.txt,
  related-ways-to-take-action/options.php, wp-security-scan/securityscan.php,
  akismet/readme.txt and wp-ids/ids-admin.php." );
	script_tag( name: "solution", value: "Update to Version 2.8.1 or later." );
	script_tag( name: "summary", value: "The host is running WordPress and is prone to Multiple Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-settings.php";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "ABSPATHwp-include" ) && ContainsString( res, "include_path" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

