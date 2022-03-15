if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902518" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)" );
	script_cve_id( "CVE-2011-1271" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "Microsoft .NET Framework Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://stackoverflow.com/questions/2135509/bug-only-occurring-when-compile-optimization-enabled/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_tag( name: "impact", value: "Successful exploitation could allow context-dependent attackers to bypass
  intended access restrictions." );
	script_tag( name: "affected", value: "Microsoft .NET Framework versions before 4 beta 2." );
	script_tag( name: "insight", value: "The flaw is due to an error in the JIT compiler, when
  'IsJITOptimizerDisabled' is set to false, fails to handle expressions
  related to null strings, which allows context-dependent attackers to bypass
  intended access restrictions in opportunistic circumstances by leveraging a crafted application." );
	script_tag( name: "solution", value: "Update to Microsoft .NET Framework version 4 beta 2 or later." );
	script_tag( name: "summary", value: "Microsoft .NET Framework is prone to a security bypass vulnerability.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902522." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

