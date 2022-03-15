CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806100" );
	script_version( "2020-04-21T10:50:58+0000" );
	script_cve_id( "CVE-2015-4497", "CVE-2015-4498" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 10:50:58 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2015-08-31 16:06:00 +0530 (Mon, 31 Aug 2015)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities (Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to multiple Vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A use-after-free vulnerability with a '<canvas>' element on a page. This
  occurs when a resize event is triggered in concert with style changes but
  the canvas references have been recreated in the meantime, destroying the
  originally referenced context. This results in an exploitable crash.

  - A vulnerability in the way Firefox handles installation of add-ons." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code by leveraging improper interaction between
  resize events and changes to Cascading Style Sheets (CSS) token sequences for
  a CANVAS element and to bypass an intended user-confirmation requirement by
  constructing a crafted data." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 40.0.3 on
  (Mac OS X)" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 40.0.3
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-94" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "40.0.3" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "40.0.3" + "\n";
	security_message( data: report );
	exit( 0 );
}

