if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801975" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "deprecated", value: TRUE );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Fraudulent Digital Certificates Spoofing Vulnerability (2607712)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2607712" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/2607712.mspx" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks or perform man-in-the-middle attacks against all Web browser
  users including users of Internet Explorer." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2003 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error when handling the fraudulent digital
  certificates issued by Comodo and it is not properly validating its
  identity." );
	script_tag( name: "solution", value: "Apply the Patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Microsoft Windows operating system is prone to a spoofing vulnerability.

  This VT has been superseded by KB2641690 Which is addressed in VT gb_ms_fraudulent_digital_cert_spoofing_vuln.nasl (OID:1.3.6.1.4.1.25623.1.0.802403)." );
	exit( 0 );
}
exit( 66 );

