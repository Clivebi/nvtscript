CPE = "cpe:/a:cisco:prime_infrastructure";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105615" );
	script_cve_id( "CVE-2016-1291" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14181 $" );
	script_name( "Cisco Prime Infrastructure Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-remcode" );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by sending an HTTP POST with crafted deserialized
  user data. An exploit could allow the attacker to execute arbitrary code with root-level privileges on the affected system, which
  could be used to conduct further attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to insufficient sanitization of HTTP user-supplied input." );
	script_tag( name: "solution", value: "Update to Cisco Prime Infrastructure 3.0.2 or newer" );
	script_tag( name: "summary", value: "A vulnerability in the web interface of Cisco Prime Infrastructure could allow an unauthenticated,
  remote attacker to execute arbitrary code on a targeted system." );
	script_tag( name: "affected", value: "Cisco Prime Infrastructure prior to 3.0.2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-21 11:49:04 +0200 (Thu, 21 Apr 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_pis_version.sc" );
	script_mandatory_keys( "cisco_pis/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^3\\." )){
	if(version_is_less( version: version, test_version: "3.0.2" )){
		fix = "3.0.2";
	}
}
if(IsMatchRegexp( version, "^2\\." )){
	if(version_is_less( version: version, test_version: "2.2.3" )){
		fix = "2.2.3 Update 4";
	}
	if(IsMatchRegexp( version, "^2\\.2\\.3" )){
		if(installed_patches = get_kb_item( "cisco_pis/installed_patches" )){
			if(!ContainsString( installed_patches, "Update 4" )){
				fix = "2.2.3 Update 4";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

