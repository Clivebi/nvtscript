CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810307" );
	script_version( "$Revision: 11607 $" );
	script_cve_id( "CVE-2016-7065" );
	script_bugtraq_id( 93462 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-09 12:42:39 +0530 (Fri, 09 Dec 2016)" );
	script_name( "Red Hat JBoss EAP Server Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is running Red Hat JBoss EAP Server
  and is prone to denial of service Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to JMX servlet
  deserializes Java objects sent via HTTP." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to cause a denial of service and possibly execute
  arbitrary code." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "affected", value: "Red Hat JBoss EAP server version 4 and 5." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40842/" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_red_hat_jboss_eap_server_detect.sc" );
	script_mandatory_keys( "Redhat/JBoss/EAP/Installed" );
	script_require_ports( "Services/www", 443 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!jbossPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!jbossVer = get_app_version( cpe: CPE, port: jbossPort )){
	exit( 0 );
}
if(IsMatchRegexp( jbossVer, "^(4|5)" )){
	if(version_is_equal( version: jbossVer, test_version: "4.0" ) || version_is_equal( version: jbossVer, test_version: "5.0" )){
		report = report_fixed_ver( installed_version: jbossVer, fixed_version: "None Available" );
		security_message( data: report, port: jbossPort );
		exit( 0 );
	}
}

