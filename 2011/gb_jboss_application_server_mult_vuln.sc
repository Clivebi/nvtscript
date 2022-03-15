if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801987" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "JBoss Application Server Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "JBoss_enterprise_aplication_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "jboss/detected" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Sep/139" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to get the  all
  services with their paths on the server and get the sensitive information." );
	script_tag( name: "affected", value: "JBoss Application Server 5.0 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Status page is publicly accessible. Which leads to leakage of logs of last
  connections and (in second case) leakage of all services (with their paths)
  on the server.

  - There is no protection against Brute Force attacks at these resources and
  other private resources with BF vulnerability. The list of all resources of
  concrete server can be found at page status?full=true." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running JBoss Application Server and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_kb_item( "jboss/port" )){
	exit( 0 );
}
url = "/status?full=true";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "Application list" ) && ContainsString( res, "WebCCReports" ) && ContainsString( res, "PortComponentLinkServlet" ) ) || ( ContainsString( res, "<title>Tomcat Status" ) && ContainsString( res, "Application list" ) && ContainsString( res, "Processing time:" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

