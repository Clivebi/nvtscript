CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801940" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_cve_id( "CVE-2011-1772", "CVE-2011-2088" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)" );
	script_name( "Apache Struts Security Update (S2-006) - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/struts/http/detected" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-006" );
	script_xref( name: "URL", value: "http://www.ventuneac.net/security-advisories/MVSA-11-006" );
	script_xref( name: "Advisory-ID", value: "S2-006" );
	script_tag( name: "summary", value: "Apache Struts is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the
  response." );
	script_tag( name: "insight", value: "The flaw is due to error in XWork, when handling the
  's:submit' element and a nonexistent method, which gives sensitive information about
  internal Java class paths." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain
  potentially sensitive information about internal Java class paths via vectors involving
  an s:submit element and a nonexistent method." );
	script_tag( name: "affected", value: "XWork version 2.2.1 in Apache Struts 2.2.1 is known
  to be vulnerable." );
	script_tag( name: "solution", value: "Update Apache Struts to version 2.2.3 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/Nonmethod.action";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Stacktraces" ) && ContainsString( res, "Nonmethod" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

