CPE = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105537" );
	script_bugtraq_id( 83105 );
	script_cve_id( "CVE-2016-1318" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_name( "Cisco Application Policy Infrastructure Controller Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/83105" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160208-apic" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient input validation of user-submitted content." );
	script_tag( name: "solution", value: "See vendor advisory." );
	script_tag( name: "summary", value: "Cisco Application Policy Infrastructure Controller is prone to a cross-site scripting vulnerability." );
	script_tag( name: "affected", value: "Cisco APIC-EM version 1.1 is affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-06 03:06:00 +0000 (Tue, 06 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-02-11 14:46:59 +0100 (Thu, 11 Feb 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_apic_em_web_detect.sc" );
	script_mandatory_keys( "cisco/apic_em/version" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(IsMatchRegexp( vers, "^1\\.1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "See vendor advisory" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

