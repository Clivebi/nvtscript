CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100821" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_cve_id( "CVE-2010-2080", "CVE-2010-3476" );
	script_bugtraq_id( 43264 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)" );
	script_name( "OTRS Core System Multiple Cross-Site Scripting and Denial of Service Vulnerabilities" );
	script_tag( name: "impact", value: "An attacker may leverage these issues to cause denial-of-service
  conditions or to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in application which fails to properly handle
  user-supplied input." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to OTRS (Open Ticket Request System) higher than 2.3.6 or 2.4.8
  or later, or apply the patch from the referenced vendor advisory." );
	script_tag( name: "summary", value: "OTRS is prone to multiple cross-site scripting vulnerabilities and a
  denial-of-service vulnerability" );
	script_tag( name: "affected", value: "OTRS versions prior to 2.3.6 and 2.4.8 are vulnerable." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43264" );
	script_xref( name: "URL", value: "http://otrs.org/" );
	script_xref( name: "URL", value: "http://otrs.org/advisory/OSA-2010-02-en/" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(IsMatchRegexp( vers, "^2\\.4" )){
		if(version_is_less( version: vers, test_version: "2.4.8" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.8" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	if(IsMatchRegexp( vers, "^2\\.3" )){
		if(version_is_less( version: vers, test_version: "2.3.6" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.6" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

