if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803688" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2010-5185" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-07-05 15:51:39 +0530 (Fri, 05 Jul 2013)" );
	script_name( "Comodo Internet Security Unspecified Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/429014.php" );
	script_xref( name: "URL", value: "http://personalfirewall.comodo.com/release_notes.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_comodo_internet_security_detect_win.sc" );
	script_mandatory_keys( "Comodo/InternetSecurity/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary code or may
  cause denial of service condition." );
	script_tag( name: "affected", value: "Comodo Internet Security versions before 5.3.174622.1216" );
	script_tag( name: "insight", value: "Flaw related to the antivirus component, does not validate the revocation
  status of the X.509 certificates in signed binaries." );
	script_tag( name: "solution", value: "Upgrade to Comodo Internet Security version 5.3.174622.1216 or later." );
	script_tag( name: "summary", value: "The host is installed with Comodo Internet Security and is prone
  to unspecified vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
Ver = get_kb_item( "Comodo/InternetSecurity/Win/Ver" );
if(Ver){
	if(version_is_less( version: Ver, test_version: "5.3.174622.1216" )){
		report = report_fixed_ver( installed_version: Ver, fixed_version: "5.3.174622.1216" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

