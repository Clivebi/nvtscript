CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140161" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2017-1121", "CVE-2016-8919" );
	script_bugtraq_id( 95650 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-13 22:20:00 +0000 (Mon, 13 Feb 2017)" );
	script_tag( name: "creation_date", value: "2017-02-14 17:22:08 +0100 (Tue, 14 Feb 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "IBM Websphere Application Server XSS and DoS Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities are due to

  - An input validation error in the 'Admin Console' of WebSphere Application Server.

  - Allowing serialized objects from untrusted sources to run." );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities
  allows users to embed arbitrary JavaScript code in the Web UI thus altering the
  intended functionality potentially leading to credentials disclosure within a
  trusted session, also can lead to a denail of service condition." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server versions
  9.0.0.0 through 9.0.0.2, 8.5.0.0 through 8.5.5.11,

  8.0.0.0 through 8.0.0.12, 7.0.0.0 through 7.0.0.41" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) 9.0.0.3, or 8.5.5.12, or 8.0.0.14, or 7.0.0.43, or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21997743" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21993797" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21992315" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^9\\.0" )){
	if( version_is_less( version: version, test_version: "9.0.0.3" ) ) {
		fix = "9.0.0.3";
	}
	else {
		if(IsMatchRegexp( version, "^8\\.5" )){
			if( version_is_less( version: version, test_version: "8.5.5.12" ) ) {
				fix = "8.5.5.12";
			}
			else {
				if(IsMatchRegexp( version, "^8\\.0" )){
					if( version_is_less( version: version, test_version: "8.0.0.14" ) ) {
						fix = "8.0.0.14";
					}
					else {
						if(IsMatchRegexp( version, "^7\\.0" )){
							if( version_is_less( version: version, test_version: "7.0.0.43" ) ) {
								fix = "7.0.0.43";
							}
							else {
								exit( 99 );
							}
						}
					}
				}
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

