if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800482" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0483" );
	script_bugtraq_id( 38463 );
	script_name( "MS Internet Explorer 'VBScript' RCE Vulnerability" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  via specially crafted attack." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.x, 7.x and 8.x." );
	script_tag( name: "insight", value: "The flaw exists in the way that 'VBScript' interacts with Windows Help files
  when using Internet Explorer. If a malicious Web site displayed a specially
  crafted dialog box and a user pressed the F1 key, it allows arbitrary code
  to be executed in the security context of the currently logged-on user." );
	script_tag( name: "summary", value: "Internet Explorer and VBScript are prone to a remote code
  execution (RCE) vulnerability." );
	script_tag( name: "solution", value: "Apply the latest updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/981169" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

