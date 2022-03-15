CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807646" );
	script_version( "2020-11-02T14:34:19+0000" );
	script_cve_id( "CVE-2016-2118", "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-0128" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-02 14:34:19 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-04-14 14:39:10 +0530 (Thu, 14 Apr 2016)" );
	script_name( "Samba Badlock Critical Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://badlock.org/" );
	script_xref( name: "URL", value: "http://thehackernews.com/2016/03/windows-samba-vulnerability.html" );
	script_tag( name: "summary", value: "This host is running Samba and is prone
  to badlock vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - multiple errors in DCE-RPC code

  - a spoofing Vulnerability in NETLOGON

  - the LDAP implementation did not enforce integrity protection for LDAP connections

  - the SSL/TLS certificates are not validated in certain connections

  - not enforcing Server Message Block (SMB) signing for clients using the SMB1 protocol

  - an integrity protection for IPC traffic is not enabled by default

  - the MS-SAMR and MS-LSAD protocol implementations mishandle DCERPC connections

  - an error in the implementation of NTLMSSP authentication" );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  leads to Man-in-the-middle (MITM) attacks, to causes denial of service, to spoof
  and to obtain sensitive session information." );
	script_tag( name: "affected", value: "Samba versions 3.0.x through 4.4.1.

  NOTE: Samba versions 4.2.11, 4.3.8 are not affected" );
	script_tag( name: "solution", value: "Upgrade to samba version 4.2.11, or 4.3.8,
  or 4.4.2, or later." );
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
if(vers == "4.2.11" || vers == "4.3.8" || vers == "4.4.2"){
	exit( 99 );
}
if(IsMatchRegexp( vers, "^[34]\\." )){
	if(version_is_less( version: vers, test_version: "4.4.2" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "4.2.11 or 4.3.8 or 4.4.2, or later", install_path: loc );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

