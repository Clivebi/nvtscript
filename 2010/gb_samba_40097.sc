CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100644" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-1635" );
	script_bugtraq_id( 40097 );
	script_name( "Samba Multiple Remote Denial of Service Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40097" );
	script_xref( name: "URL", value: "https://bugzilla.samba.org/show_bug.cgi?id=7254" );
	script_xref( name: "URL", value: "http://samba.org/samba/history/samba-3.4.8.html" );
	script_xref( name: "URL", value: "http://samba.org/samba/history/samba-3.5.2.html" );
	script_tag( name: "summary", value: "Samba is prone to multiple remote denial-of-service vulnerabilities." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to crash the application, denying
  service to legitimate users." );
	script_tag( name: "affected", value: "Versions prior to Samba 3.4.8 and 3.5.2 are vulnerable." );
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
if(version_in_range( version: vers, test_version: "3.5", test_version2: "3.5.1" ) || version_in_range( version: vers, test_version: "3.4", test_version2: "3.4.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.4.8/3.5.2 or later", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

