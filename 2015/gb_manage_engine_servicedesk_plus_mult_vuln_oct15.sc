CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806509" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-10-21 12:04:52 +0530 (Wed, 21 Oct 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "ManageEngine ServiceDesk Plus Multiple Vulnerabilities - Oct15" );
	script_tag( name: "summary", value: "This host is installed with ManageEngine
  ServiceDesk and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to enumerate user and domain or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Insufficient validation of some requests to url.

  - Improper access control to do certain functionality like viewing the
  subjects of the tickets, stats and other information related to tickets.

  - Insufficient sanitization of user supplied input via 'site' variable in
  'CreateReportTable.jsp' page." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to enumerate users and get some sensitive information, to gain
  complete access to database/system." );
	script_tag( name: "affected", value: "ManageEngine ServiceDesk Plus version 9.0
  before 9.0 Build 9031(Other versions could also be affected)." );
	script_tag( name: "solution", value: "Upgrade to ManageEngine ServiceDesk Plus
  version 9.0 Build 9031 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/35891" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/35904" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/35890" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manageengine_servicedesk_plus_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "manageengine/servicedesk_plus/detected" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/domainServlet/AJaxDomainServlet?action=searchLocalAuthDomain&search=guest";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "USER_PRESENT", extra_check: make_list( "IN_SITE",
	 "ADD_REQUESTER" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

