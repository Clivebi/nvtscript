CPE = "cpe:/a:avg:anti-virus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810835" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_cve_id( "CVE-2017-5566" );
	script_bugtraq_id( 97022 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-04 17:45:27 +0530 (Tue, 04 Apr 2017)" );
	script_name( "AVG Antivirus Code Injection Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with AVG Antivirus
  and is prone to code injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to:

  - No use of Protected Processes feature, and therefore an attacker can enter an
    arbitrary Application Verifier Provider DLL under Image File Execution Options
    in the registry.

  - The self-protection mechanism is intended to block all local processes
    (regardless of privileges) from modifying Image File Execution Options for these
    products." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow a local attacker to bypass a self-protection
  mechanism, inject arbitrary code, and take full control of any AVG process
  via a 'DoubleAgent' attack." );
	script_tag( name: "affected", value: "AVG Antivirus 17.1 and earlier on Windows" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_avg_detect_win.sc" );
	script_mandatory_keys( "avg/antivirus/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "17.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

