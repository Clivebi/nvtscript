CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811522" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-11103" );
	script_bugtraq_id( 99551 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-07-13 12:28:31 +0530 (Thu, 13 Jul 2017)" );
	script_name( "Samba Man in the Middle Security Bypass Vulnerability (Heimdal)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2017-11103.html" );
	script_tag( name: "summary", value: "Samba is prone to a MITM authentication validation bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in function
  '_krb5_extract_ticket' where the KDC-REP service name must be obtained from
  encrypted version stored in 'enc_part' instead of the unencrypted version
  stored in 'ticket'. Use of the unecrypted version provides an opportunity
  for successful server impersonation and other attacks." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow
  a MITM attacker to impersonate a trusted server and thus gain elevated access
  to the domain by returning malicious replication or authorization data." );
	script_tag( name: "affected", value: "All versions of Samba from 4.0.0 before
  4.6.6 or 4.5.12 or 4.4.15.

  Note: All versions of Samba from 4.0.0 onwards using embedded Heimdal Kerberos.
  Samba binaries built against MIT Kerberos are not vulnerable." );
	script_tag( name: "solution", value: "Upgrade to Samba 4.6.6 or 4.5.12 or 4.4.15
  or later or apply the patch from below." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security" );
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
if(IsMatchRegexp( vers, "^4\\." )){
	if( version_is_less( version: vers, test_version: "4.4.15" ) ){
		fix = "4.4.15";
	}
	else {
		if( IsMatchRegexp( vers, "^4\\.5" ) && version_is_less( version: vers, test_version: "4.5.12" ) ){
			fix = "4.5.12";
		}
		else {
			if(IsMatchRegexp( vers, "^4\\.6" ) && version_is_less( version: vers, test_version: "4.6.6" )){
				fix = "4.6.6";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

