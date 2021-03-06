CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103095" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2011-03-01 13:10:12 +0100 (Tue, 01 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 46597 );
	script_cve_id( "CVE-2011-0719" );
	script_name( "Samba 'FD_SET' Memory Corruption Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46597" );
	script_xref( name: "URL", value: "http://samba.org/samba/security/CVE-2011-0719.html" );
	script_tag( name: "summary", value: "Samba is prone to a memory-corruption vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to crash the application or cause
  the application to enter an infinite loop. Due to the nature of this issue, arbitrary code execution may
  be possible but this has not been confirmed." );
	script_tag( name: "affected", value: "Samba versions prior to 3.5.7 are vulnerable." );
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
if(version_is_less( version: vers, test_version: "3.5.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.5.7", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

