if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803694" );
	script_version( "2021-08-13T07:21:38+0000" );
	script_cve_id( "CVE-2009-5125" );
	script_bugtraq_id( 34737 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 07:21:38 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-07-05 17:08:06 +0530 (Fri, 05 Jul 2013)" );
	script_name( "Comodo Internet Security Scan Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/428996.php" );
	script_xref( name: "URL", value: "http://personalfirewall.comodo.com/release_notes.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_comodo_internet_security_detect_win.sc" );
	script_mandatory_keys( "Comodo/InternetSecurity/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to bypass malware detection via
  manipulation of the archive file format." );
	script_tag( name: "affected", value: "Comodo Internet Security versions before 3.9.95478.509" );
	script_tag( name: "insight", value: "Flaw exists in the parsing engine and can be bypassed by a specially crafted
  and formatted RAR archive." );
	script_tag( name: "solution", value: "Upgrade to Comodo Internet Security version 3.9.95478.509 or later." );
	script_tag( name: "summary", value: "The host is installed with Comodo Internet Security and is prone
  to scan bypass vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
Ver = get_kb_item( "Comodo/InternetSecurity/Win/Ver" );
if(Ver){
	if(version_is_less( version: Ver, test_version: "3.9.95478.509" )){
		report = report_fixed_ver( installed_version: Ver, fixed_version: "3.9.95478.509" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

