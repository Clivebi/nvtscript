CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811712" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7809", "CVE-2017-7784", "CVE-2017-7802", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7753", "CVE-2017-7787", "CVE-2017-7807", "CVE-2017-7792", "CVE-2017-7791", "CVE-2017-7803", "CVE-2017-7779" );
	script_bugtraq_id( 100196, 100197, 100203, 100202, 100206, 100315, 100234, 100242, 100240, 100243, 100201 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:04:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "creation_date", value: "2017-08-21 12:56:34 +0530 (Mon, 21 Aug 2017)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2017-20) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use-after-free in WebSockets during disconnection.

  - Use-after-free with marquee during window resizing.

  - Use-after-free while deleting attached editor DOM node.

  - Use-after-free with image observers.

  - Use-after-free resizing image elements.

  - Buffer overflow manipulating ARIA attributes in DOM.

  - Buffer overflow while painting non-displayable SVG.

  - Out-of-bounds read with cached style data and pseudo-elements.

  - Same-origin policy bypass with iframes through page reloads.

  - Domain hijacking through AppCache fallback.

  - Buffer overflow viewing certificates with an extremely long OID.

  - Spoofing following page navigation with data: protocol and modal alerts.

  - CSP containing sandbox improperly applied.

  - Memory safety bugs fixed in Firefox 55, Firefox ESR 52.3, and Thunderbird 52.3." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to gain access to potentially sensitive information,
  execute arbitrary code and conduct a denial-of-service condition." );
	script_tag( name: "affected", value: "Mozilla Thunderbird versions before 52.3." );
	script_tag( name: "solution", value: "Update to version 52.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-20/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "52.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "52.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

