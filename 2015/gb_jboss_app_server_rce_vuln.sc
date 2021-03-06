CPE = "cpe:/a:redhat:jboss_wildfly_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806623" );
	script_version( "$Revision: 11423 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-17 09:35:16 +0200 (Mon, 17 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-17 16:28:17 +0530 (Tue, 17 Nov 2015)" );
	script_name( "JBoss WildFly Application Server Remote Code Execution Vulnerability" );
	script_tag( name: "summary", value: "The host is running JBoss WildFly
  Application Server and is prone to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to presence
  of a deserialization error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "JBoss WildFly Application Server versions
  before 9.0.2" );
	script_tag( name: "solution", value: "No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jboss" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_jboss_wildfly_detect.sc" );
	script_mandatory_keys( "JBoss/WildFly/installed" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!webPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!webVer = get_app_version( cpe: CPE, port: webPort )){
	exit( 0 );
}
if(version_is_less_equal( version: webVer, test_version: "9.0.2" )){
	report = "Installed Version:  " + webVer + "\n" + "Solution            None Available" + "\n";
	security_message( data: report, port: webPort );
	exit( 0 );
}

