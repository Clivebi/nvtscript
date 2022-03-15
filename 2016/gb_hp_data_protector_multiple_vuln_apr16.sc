CPE = "cpe:/a:hp:data_protector";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807814" );
	script_version( "2021-08-09T06:49:35+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 06:49:35 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-04-26 18:03:24 +0530 (Tue, 26 Apr 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-2004", "CVE-2016-2005", "CVE-2016-2006", "CVE-2016-2007", "CVE-2016-2008", "CVE-2015-2808" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP Data Protector Multiple Vulnerabilities (Apr 2016)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "hp_data_protector_installed.sc" );
	script_require_ports( "Services/hp_dataprotector", 5555 );
	script_mandatory_keys( "microfocus/data_protector/detected" );
	script_tag( name: "summary", value: "HP Data Protector is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as,

  - Data Protector does not authenticate users, even with Encrypted Control
    Communications enabled.

  - Data Protector contains an embedded SSL private key.

  - Some other unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system and also gain
  access to potentially sensitive information." );
	script_tag( name: "affected", value: "HP Data Protector before 7.03_108, 8.x before 8.15 and
  9.x before 9.06." );
	script_tag( name: "solution", value: "Update to version 7.03_108, 8.15, 9.06 or later." );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/267328" );
	script_xref( name: "URL", value: "http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05085988" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
build = get_kb_item( "microfocus/data_protector/" + port + "/build" );
if( IsMatchRegexp( vers, "^09\\." ) ){
	if(version_is_less( version: vers, test_version: "09.06" )){
		fix = "09.06";
		VULN = TRUE;
	}
}
else {
	if( IsMatchRegexp( vers, "^08\\." ) ){
		if(version_is_less( version: vers, test_version: "08.15" )){
			fix = "08.15";
			VULN = TRUE;
		}
	}
	else {
		if( build && IsMatchRegexp( vers, "^07\\.03" ) ){
			if(version_is_less( version: build, test_version: "108" )){
				report = report_fixed_ver( installed_version: vers + "_" + build, fixed_version: "07.03_108" );
				security_message( data: report, port: port );
				exit( 0 );
			}
		}
		else {
			if(version_is_less( version: vers, test_version: "07.03" )){
				fix = "07.03_108";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

