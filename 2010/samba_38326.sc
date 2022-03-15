CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100499" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-02-22 14:49:01 +0100 (Mon, 22 Feb 2010)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 38326 );
	script_cve_id( "CVE-2010-0547", "CVE-2011-2724" );
	script_name( "Samba 'client/mount.cifs.c' Remote Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38326" );
	script_xref( name: "URL", value: "http://git.samba.org/?p=samba.git;a=commit;h=a065c177dfc8f968775593ba00dffafeebb2e054" );
	script_tag( name: "summary", value: "Samba is prone to a remote denial-of-service vulnerability." );
	script_tag( name: "impact", value: "A remote attacker can exploit this issue to crash the affected
  application, denying service to legitimate users." );
	script_tag( name: "affected", value: "Samba 3.5.10 and earlier are vulnerable." );
	script_tag( name: "solution", value: "Upgrade to Samba version 3.5.11 or later." );
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
if(version_is_less( version: vers, test_version: "3.5.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.5.11 or later", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

