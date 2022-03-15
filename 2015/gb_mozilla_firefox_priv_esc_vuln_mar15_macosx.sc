CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805515" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2015-0818" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-03-27 14:36:15 +0530 (Fri, 27 Mar 2015)" );
	script_name( "Mozilla Firefox SVG Navigation Privilege Escalation Vulnerability Mar15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  docshell/base/nsDocShell.cpp within the SVG format content navigation
  functionality." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain elevated privileges and execute arbitrary scripts with the
  elevated privileges." );
	script_tag( name: "affected", value: "Mozilla Firefox before version 36.0.4 on
  Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 36.0.4
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031959" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-28" );
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
if(version_is_less( version: ffVer, test_version: "36.0.4" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     36.0.4\n";
	security_message( data: report );
	exit( 0 );
}

