CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813785" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-1140" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-17 14:46:20 +0530 (Fri, 17 Aug 2018)" );
	script_name( "Samba 'DNS and LDAP' DoS Vulnerability (Aug 2018)" );
	script_tag( name: "summary", value: "Samba is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to missing null pointer
  checks." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct a denial of service attack." );
	script_tag( name: "affected", value: "Samba versions 4.8.0 onwards." );
	script_tag( name: "solution", value: "Update to version 4.8.4 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2018-1140.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/history/samba-4.8.4.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
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
if(version_in_range( version: vers, test_version: "4.8.0", test_version2: "4.8.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.8.4 or apply patch", install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

