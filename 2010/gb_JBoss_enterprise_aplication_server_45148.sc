if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100931" );
	script_version( "2020-04-01T10:41:43+0000" );
	script_tag( name: "last_modification", value: "2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)" );
	script_bugtraq_id( 45148 );
	script_cve_id( "CVE-2010-3708", "CVE-2010-3862", "CVE-2010-3878" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "JBoss Enterprise Application Platform Multiple Remote Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "JBoss_enterprise_aplication_server_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "jboss/detected" );
	script_tag( name: "solution", value: "Updates are available, please see the references for more information." );
	script_tag( name: "summary", value: "The JBoss Enterprise Application Platform is prone to multiple vulnerabilities,
  including a remote code-execution issue, a remote denial-of-service issue, and a cross-site request-forgery issue." );
	script_tag( name: "impact", value: "Successful exploits can allow attackers to execute arbitrary code within the context
  of the affected application, perform certain administrative actions, deploy arbitrary WAR files on the server, or
  cause denial-of-service conditions, other attacks may also be possible." );
	script_tag( name: "affected", value: "These issues affect JBoss Enterprise Application Platform 4.3.0, other
  versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:redhat:jboss_application_server",
	 "cpe:/a:jboss:jboss_application_server",
	 "cpe:/a:redhat:jboss_enterprise_application_platform" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!vers = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(ContainsString( vers, "cp" )){
	vers = str_replace( string: vers, find: "cp", replace: "." );
}
if(ContainsString( vers, "GA" )){
	vers = vers - ".GA";
}
if(version_is_less( version: vers, test_version: "4.3.0.9" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.3.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

