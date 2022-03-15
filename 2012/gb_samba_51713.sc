CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103411" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-02-09 10:12:15 +0100 (Thu, 09 Feb 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 51713 );
	script_cve_id( "CVE-2012-0817" );
	script_name( "Samba Memory Leak Local Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51713" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2012-0817" );
	script_tag( name: "summary", value: "Samba is prone to a local denial-of-service vulnerability." );
	script_tag( name: "impact", value: "A local attacker can exploit this issue to exhaust available memory,
  denying access to legitimate users." );
	script_tag( name: "affected", value: "The vulnerability affects Samba versions 3.6.0 through 3.6.2." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
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
if(version_in_range( version: vers, test_version: "3.6", test_version2: "3.6.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.6.3", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

