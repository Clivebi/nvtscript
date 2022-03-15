CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100803" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-09-15 16:23:15 +0200 (Wed, 15 Sep 2010)" );
	script_bugtraq_id( 43212 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3069" );
	script_name( "Samba SID Parsing Remote Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43212" );
	script_xref( name: "URL", value: "http://us1.samba.org/samba/history/samba-3.5.5.html" );
	script_xref( name: "URL", value: "http://us1.samba.org/samba/security/CVE-2010-2069.html" );
	script_tag( name: "summary", value: "Samba is prone to a remote stack-based buffer-overflow vulnerability
  because it fails to properly bounds-check user-supplied data before
  copying it to an insufficiently sized memory buffer." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will
  likely result in a denial of service." );
	script_tag( name: "affected", value: "Samba versions prior to 3.5.5 are vulnerable." );
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
if(version_is_less( version: vers, test_version: "3.5.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.5.5", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

