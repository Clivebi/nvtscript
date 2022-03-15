CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100476" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 37992 );
	script_cve_id( "CVE-2009-3297", "CVE-2010-0787" );
	script_name( "Samba 'mount.cifs' Utility Local Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37992" );
	script_tag( name: "summary", value: "Samba is prone to a local privilege-escalation vulnerability in the
  'mount.cifs' utility." );
	script_tag( name: "impact", value: "Local attackers can exploit this issue to gain elevated privileges on
  affected computers." );
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
if(version_is_less_equal( version: vers, test_version: "3.4.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.4.6", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

