CPE = "cpe:/a:novell:file_reporter";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801918" );
	script_version( "2019-05-17T10:45:27+0000" );
	script_tag( name: "last_modification", value: "2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)" );
	script_cve_id( "CVE-2011-0994" );
	script_bugtraq_id( 47144 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-11-116/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/517321/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_novell_prdts_detect_win.sc" );
	script_mandatory_keys( "Novell/FileReporter/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service." );
	script_tag( name: "affected", value: "Novell File Reporter (NFR) before 1.0.2" );
	script_tag( name: "insight", value: "The flaw exists within 'NFRAgent.exe' module, which allows remote attackers
  to execute arbitrary code via unspecified XML data to port 3037." );
	script_tag( name: "solution", value: "Upgrade Novell File Reporter 1.0.2 or later." );
	script_tag( name: "summary", value: "This host is installed with Novell File Reporter and is prone to
  buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://download.novell.com/Download?buildid=rCAgCcbPH9s~" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "1.0.117" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

