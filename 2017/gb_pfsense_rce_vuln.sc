CPE = "cpe:/a:pfsense:pfsense";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112135" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-30 14:57:00 +0000 (Thu, 30 May 2019)" );
	script_tag( name: "creation_date", value: "2017-11-23 08:35:21 +0100 (Thu, 23 Nov 2017)" );
	script_name( "pfSense Remote Code Execution & Cross-Site Request Forgery Vulnerability" );
	script_cve_id( "CVE-2017-1000479" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_tag( name: "summary", value: "pfSense is prone to a remote code execution (RCE) and cross-site request forgery
  (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The pfSense WebGUI is vulnerable to clickjacking.
By tricking an authenticated admin into interacting with a specially crafted webpage it is possible for an attacker
to execute arbitrary code in the WebGUI." );
	script_tag( name: "impact", value: "Since the WebGUI runs as the root user, this will result in a full compromise of the pfSense instance." );
	script_tag( name: "affected", value: "pfSense before version 2.4.2" );
	script_tag( name: "solution", value: "Upgrade to version 2.4.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.securify.nl/advisory/SFY20171101/clickjacking-vulnerability-in-csrf-error-page-pfsense.html" );
	script_xref( name: "URL", value: "https://doc.pfsense.org/index.php/2.4.2_New_Features_and_Changes" );
	script_xref( name: "URL", value: "https://www.netgate.com/blog/pfsense-2-4-2-release-p1-and-2-3-5-release-p1-now-available.html" );
	script_dependencies( "gb_pfsense_detect.sc" );
	script_mandatory_keys( "pfsense/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ver = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "2.4.2" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.4.2-RELEASE" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

