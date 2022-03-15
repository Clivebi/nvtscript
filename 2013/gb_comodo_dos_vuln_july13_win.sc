if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803695" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-2273" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-07-16 12:47:17 +0530 (Tue, 16 Jul 2013)" );
	script_name( "Comodo Internet Security Denial of Service Vulnerability July 13" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2012/Apr/13" );
	script_xref( name: "URL", value: "http://www.comodo.com/home/download/release-notes.php?p=anti-malware" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_comodo_internet_security_detect_win.sc" );
	script_mandatory_keys( "Comodo/InternetSecurity/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to cause denial of service condition
  via crafted Portable Executable (PE) file." );
	script_tag( name: "affected", value: "Comodo Internet Security versions before 5.10.228257.2253 on Windows 7 x64" );
	script_tag( name: "insight", value: "Issue is triggered when handling executables with that contain kernels with
  imagebase values." );
	script_tag( name: "solution", value: "Upgrade to Comodo Internet Security version 5.10.228257.2253 or later." );
	script_tag( name: "summary", value: "The host is installed with Comodo Internet Security and is prone
  to denial of service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.comodo.com/home/internet-security/free-internet-security.php" );
	exit( 0 );
}
require("version_func.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win7x64: 2 ) <= 0){
	exit( 0 );
}
Ver = get_kb_item( "Comodo/InternetSecurity/Win/Ver" );
if(Ver){
	if(version_is_less( version: Ver, test_version: "5.10.228257.2253" )){
		report = report_fixed_ver( installed_version: Ver, fixed_version: "5.10.228257.2253" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

