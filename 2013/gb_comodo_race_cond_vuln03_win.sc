if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803686" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2010-5157" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-07-05 15:35:47 +0530 (Fri, 05 Jul 2013)" );
	script_name( "Comodo Internet Security Race Condition Vulnerability-03" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40094" );
	script_xref( name: "URL", value: "http://personalfirewall.comodo.com/release_notes.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_comodo_internet_security_detect_win.sc" );
	script_mandatory_keys( "Comodo/InternetSecurity/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows local attacker to bypass certain security
  features." );
	script_tag( name: "affected", value: "Comodo Internet Security versions before 4.1.149672.916" );
	script_tag( name: "insight", value: "Flaw due to improper implementation of security checks in certain kernel
  hooks." );
	script_tag( name: "solution", value: "Upgrade to Comodo Internet Security version 4.1.149672.916 or later." );
	script_tag( name: "summary", value: "The host is installed with Comodo Internet Security and is prone
  to race condition vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
Ver = get_kb_item( "Comodo/InternetSecurity/Win/Ver" );
if(Ver){
	if(version_is_less( version: Ver, test_version: "4.1.149672.916" )){
		report = report_fixed_ver( installed_version: Ver, fixed_version: "4.1.149672.916" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

