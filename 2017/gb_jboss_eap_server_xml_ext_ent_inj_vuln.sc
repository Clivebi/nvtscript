CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107199" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-22 17:05:17 +0200 (Mon, 22 May 2017)" );
	script_cve_id( "CVE-2017-7464" );
	script_bugtraq_id( 98450 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "RedHat JBoss Enterprise Application Platform XML External Entity Injection Vulnerability" );
	script_tag( name: "summary", value: "RedHat JBoss Enterprise Application Platform (EAP) is prone to an
  XML External Entity injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When parsing XML which does entity expansion the SAXParserFactory
  used in EAP expands external entities, even when XMLConstants.FEATURE_SECURE_PROCESSING is set to true." );
	script_tag( name: "impact", value: "Attackers can exploit this  issue to gain access to sensitive information
  or cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Red Hat JBoss EAP server EAP 7.0.5 and 7.1.0" );
	script_tag( name: "solution", value: "Mitigation: Enable the security features of the DocumentBuilderFactory or SaxParserFactory as described by OWASP below." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/98450" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_red_hat_jboss_eap_server_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Redhat/JBoss/EAP/Installed", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 443 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!Ver = get_app_version( cpe: CPE, port: Port )){
	exit( 0 );
}
if( IsMatchRegexp( Ver, "^7\\.0" ) ){
	if(version_is_less( version: Ver, test_version: "7.0.5" )){
		Vuln = TRUE;
	}
}
else {
	if(IsMatchRegexp( Ver, "^7\\.1" )){
		if(version_is_less( version: Ver, test_version: "7.1.0" )){
			Vuln = TRUE;
		}
	}
}
if(Vuln){
	report = report_fixed_ver( installed_version: Ver, fixed_version: "Mitigation" );
	security_message( port: Port, data: report );
	exit( 0 );
}
exit( 99 );

