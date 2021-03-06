if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900190" );
	script_version( "2021-09-03T08:47:58+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 08:47:58 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-0125" );
	script_bugtraq_id( 33151 );
	script_name( "OpenSSL DSA_do_verify() Security Bypass Vulnerability in NASL" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=479655" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2009/01/12/4" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=511517" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "summary", value: "The NASL interpreter is prone to a security bypass
  vulnerability." );
	script_tag( name: "solution", value: "No solution is required.

  Note: The upstream vendor has disputed this issue, stating 'while we do misuse this function (this
  is a bug), it has absolutely no security ramification.'." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

