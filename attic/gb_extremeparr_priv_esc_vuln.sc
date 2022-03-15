if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811259" );
	script_version( "2021-10-04T14:22:38+0000" );
	script_cve_id( "CVE-2017-3622" );
	script_bugtraq_id( 97774 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-28 19:15:41 +0530 (Fri, 28 Jul 2017)" );
	script_name( "SUN Solaris Privilege Escalation Vulnerability (Extremeparr)" );
	script_tag( name: "summary", value: "Solaris is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in
  'Common Desktop Environment (CDE)' sub component of the application." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to gain elevated privileges on the affected system." );
	script_tag( name: "affected", value: "Oracle Sun Solaris version 7, 8, 9 and
  10.

  Note: Oracle Sun Solaris version 7, 8, 9 are not supported anymore and will
  not be patched." );
	script_tag( name: "solution", value: "Apply latest patch available for Oracle
  Sun Solaris version 10 or upgrade to Oracle Sun Solaris version 11." );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixSUNS" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Solaris Local Security Checks" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

