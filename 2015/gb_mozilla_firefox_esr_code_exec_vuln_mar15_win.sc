CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805510" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-0817" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-03-27 11:46:34 +0530 (Fri, 27 Mar 2015)" );
	script_name( "Mozilla Firefox ESR Just-in-time (JIT) Code Execution Vulnerability Mar15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR
  and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an out-of-bounds access
  error in asmjs/AsmJSValidate.cpp within the JavaScript Just-in-time Compilation
  (JIT)" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR 31.x before 31.5.2 on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version
  31.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031958" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-29" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^31\\." )){
	if(( version_in_range( version: vers, test_version: "31.0", test_version2: "31.5.1" ) )){
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + "31.5.2" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

