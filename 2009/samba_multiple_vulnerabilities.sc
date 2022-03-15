CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100306" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-10-15 20:14:59 +0200 (Thu, 15 Oct 2009)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_bugtraq_id( 36363, 36572, 36573 );
	script_cve_id( "CVE-2009-2813", "CVE-2009-2948", "CVE-2009-2906" );
	script_name( "Samba multiple vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36363" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36573" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36572" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2009-2813.html" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2009-2948.html" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2009-2906.html" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/history/security.html" );
	script_tag( name: "affected", value: "Versions prior to Samba 3.4.2, 3.3.8, 3.2.15, and 3.0.37 are
  vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Samba is prone to multiple vulnerabilities including a vulnerability
  that may allow attackers to bypass certain security restrictions, an
  information-disclosure vulnerability and a remote denial-of-service vulnerability." );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to gain access to resources
  that aren't supposed to be shared, allow attackers to obtain sensitive
  information that may aid in further attacks and to cause the
  application to consume excessive CPU resources, denying service to legitimate users." );
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
if(version_in_range( version: vers, test_version: "3.4", test_version2: "3.4.1" ) || version_in_range( version: vers, test_version: "3.3", test_version2: "3.3.7" ) || version_in_range( version: vers, test_version: "3.2", test_version2: "3.2.14" ) || version_in_range( version: vers, test_version: "3.0", test_version2: "3.0.36" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.37/3.2.15/3.3.8/3.4.2", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

