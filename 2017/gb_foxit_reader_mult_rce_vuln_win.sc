CPE = "cpe:/a:foxitsoftware:reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811585" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-10952", "CVE-2017-10951" );
	script_bugtraq_id( 100412, 100409 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-21 13:07:23 +0530 (Mon, 21 Aug 2017)" );
	script_name( "Foxit Reader Multiple Remote Code Execution Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Foxit Reader
  and is prone to multiple remote code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The lack of proper validation of user-supplied data in the 'saveAs JavaScript'
    function, which can lead to writing arbitrary files into attacker controlled
    locations.

  - The lack of proper validation of a user-supplied string before using it to
    execute a system call in app.launchURL method." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute code under the context of the current process." );
	script_tag( name: "affected", value: "All Foxit Reader versions on windows
  with 'Safe reading mode' feature disabled." );
	script_tag( name: "solution", value: "Mitigation is available,
  Safe reading mode should be enabled always and additionally users can also
  uncheck the 'Enable JavaScript Actions' from Foxit's Preferences menu,
  although this may break some functionality." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod", value: "30" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-17-691" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-17-692" );
	script_xref( name: "URL", value: "https://www.zerodayinitiative.com/blog/2017/8/17/busting-myths-in-foxit-reader" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_reader_detect_portable_win.sc" );
	script_mandatory_keys( "foxit/reader/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(foxitVer = get_app_version( cpe: CPE, nofork: TRUE )){
	report = report_fixed_ver( installed_version: foxitVer, fixed_version: "Mitigation" );
	security_message( data: report );
	exit( 0 );
}

