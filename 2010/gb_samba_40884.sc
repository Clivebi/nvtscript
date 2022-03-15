CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100680" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 40884 );
	script_cve_id( "CVE-2010-2063" );
	script_name( "Samba 'SMB1 Packet Chaining' Unspecified Remote Memory Corruption Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40884" );
	script_xref( name: "URL", value: "http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=873" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2010-2063.html" );
	script_tag( name: "summary", value: "Samba is prone to an unspecified memory-corruption vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code in the
  context of the application. Failed attacks may cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Samba versions prior to 3.3.13 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(version_in_range( version: vers, test_version: "3", test_version2: "3.3.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.3.13", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

