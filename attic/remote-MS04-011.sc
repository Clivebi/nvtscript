if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101011" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-03-15 22:32:35 +0100 (Sun, 15 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2003-0533", "CVE-2003-0663", "CVE-2003-0719", "CVE-2003-0806", "CVE-2003-0906", "CVE-2003-0907", "CVE-2003-0908", "CVE-2003-0909", "CVE-2003-0910", "CVE-2004-0117", "CVE-2004-0118", "CVE-2004-0119", "CVE-2004-0120", "CVE-2004-0123" );
	script_name( "MS04-011 security check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Windows : Microsoft Bulletins" );
	script_tag( name: "solution", value: "Microsoft has released a patch to fix these issues." );
	script_tag( name: "summary", value: "Windows operating system are affected to multiple remote code
  execution and privileges escalation vulnerabilities." );
	script_tag( name: "impact", value: "An attacker who successfully exploited the most severe of these vulnerabilities could take
  complete control of an affected system, including:

  - installing programs

  - viewing, changing, or deleting data

  - creating new accounts that have full privileges." );
	script_tag( name: "insight", value: "These vulnerabilities includes:

  LSASS Remote Code Execution Vulnerability - CAN-2003-0533

  LDAP Denial Of Service Vulnerability - CAN-2003-0663

  PCT Remote Code Execution Vulnerability - CAN-2003-0719

  Winlogon Remote Code Execution Vulnerability - CAN-2003-0806

  Metafile Remote Code Execution Vulnerability - CAN-2003-0906

  Help and Support Center Remote Code Execution Vulnerability - CAN-2003-0907

  Utility Manager Privilege Elevation Vulnerability - CAN-2003-0908

  Windows Management Privilege Elevation Vulnerability - CAN-2003-0909

  Local Descriptor Table Privilege Elevation Vulnerability - CAN-2003-0910

  H.323 Remote Code Execution Vulnerability - CAN-2004-0117

  Virtual DOS Machine Privilege Elevation Vulnerability - CAN-2004-0118

  Negotiate SSP Remote Code Execution Vulnerability - CAN-2004-0119

  SSL Denial Of Service Vulnerability - CAN-2004-0120

  ASN.1 Double Free Vulnerability - CAN-2004-0123." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

