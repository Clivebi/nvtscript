CPE = "cpe:/a:cisco:prime_collaboration_assurance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810677" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-3843", "CVE-2017-3844", "CVE-2017-3845" );
	script_bugtraq_id( 96248, 96247, 96245 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-25 01:29:00 +0000 (Tue, 25 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-23 10:34:46 +0530 (Thu, 23 Mar 2017)" );
	script_name( "Cisco Prime Collaboration Assurance Multiple Vulnerabilities - Mar17" );
	script_tag( name: "summary", value: "This host is running cisco prime collaboration
  assurance and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The lack of proper input validation of HTTP requests.

  - An insufficient validation of user-supplied input by the web-based management
    interface." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to view file directory listings and download files, conduct a
  cross-site scripting (XSS) attack and download system files that should be
  restricted." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "affected", value: "Cisco Prime Collaboration Assurance
  versions 11.0.0, 11.1.0 and 11.5.0" );
	script_tag( name: "solution", value: "Apply patch from the vendor advisory.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-pcp2" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-pcp3" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_pca_version.sc" );
	script_mandatory_keys( "cisco_pcp/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^11\\.[015]" )){
	if(version_is_equal( version: version, test_version: "11.0.0" ) || version_is_equal( version: version, test_version: "11.1.0" ) || version_is_equal( version: version, test_version: "11.5.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "Apply Patch" );
		security_message( data: report, port: 0 );
		exit( 0 );
	}
}
exit( 0 );

