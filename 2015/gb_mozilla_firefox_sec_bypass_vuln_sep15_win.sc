CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805746" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-4498" );
	script_bugtraq_id( 76505 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-09-25 15:47:42 +0530 (Fri, 25 Sep 2015)" );
	script_name( "Mozilla Firefox Security Bypass Vulnerability - Sep15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as add-on's URL
  failure to handle exceptional conditions." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to manipulate a user into falsely believing a trusted site has
  initiated the installation. This could lead to users installing an add-on
  from a malicious source." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 40.0.3 on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 40.0.3
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-95/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
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

