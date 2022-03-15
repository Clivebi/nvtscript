if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71307" );
	script_cve_id( "CVE-2012-1183", "CVE-2012-1184" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-21 (Asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Asterisk, the worst of
    which may allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All Asterisk users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.8.10.1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-21" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=408431" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2012-002.txt" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2012-003.txt" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-21." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-misc/asterisk", unaffected: make_list( "ge 1.8.10.1" ), vulnerable: make_list( "lt 1.8.10.1" ) ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

