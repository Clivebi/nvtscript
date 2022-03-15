CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900684" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1886" );
	script_bugtraq_id( 35472 );
	script_name( "Samba Format String Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35539" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1664" );
	script_tag( name: "affected", value: "Samba 3.2.0 through 3.2.12 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to: format string error in 'smbclient' utility when
  processing file names containing command arguments." );
	script_tag( name: "solution", value: "Upgrade to version 3.2.13 or later." );
	script_tag( name: "summary", value: "The host has Samba installed and is prone to Format String
  Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to crash an affected client
  or execute arbitrary code." );
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
if(version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.2.13", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

