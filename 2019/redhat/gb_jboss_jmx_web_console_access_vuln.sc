CPE = "cpe:/a:redhat:jboss_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142595" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2019-07-12 06:01:03 +0000 (Fri, 12 Jul 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2007-1036" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "JBoss Console and Web Management Misconfiguration Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "JBoss_enterprise_aplication_server_detect.sc" );
	script_mandatory_keys( "jboss/detected" );
	script_tag( name: "summary", value: "The default configuration of JBoss does not restrict access to the console and
  web management interfaces, which allows remote attackers to bypass authentication and gain administrative access
  via direct requests." );
	script_tag( name: "vuldetect", value: "Checks if the jmx-console or web-console is accessible without authentication." );
	script_tag( name: "solution", value: "As stated by Red Hat, the JBoss AS console manager should always be secured
  prior to deployment, as directed in the JBoss Application Server Guide and release notes. By default, the JBoss
  AS installer gives users the ability to password protect the console manager. If the user did not use the
  installer, the raw JBoss services will be in a completely unconfigured state and these steps should be performed
  manually. See the referenced advisories for mitigation steps." );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/632656/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/460597/100/0/threaded" );
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
url = dir + "/web-console/ServerInfo.jsp";
if(http_vuln_check( port: port, url: url, pattern: "<title>JBoss Management Console - Server Information</title>", check_header: TRUE, extra_check: "Management Console" )){
	report = "It was possible to access the JBoss Web Console at " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
url = dir + "/jmx-console/";
if(http_vuln_check( port: port, url: url, pattern: "<title>JBoss JMX Management Console", check_header: TRUE )){
	report += "\n\nIt was possible to access the JBoss JMX Management Console at " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
}
if(report){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

