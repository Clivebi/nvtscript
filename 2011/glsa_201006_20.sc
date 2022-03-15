if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69023" );
	script_version( "$Revision: 14171 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-2726", "CVE-2009-2346", "CVE-2009-4055", "CVE-2009-3727", "CVE-2008-7220" );
	script_name( "Gentoo Security Advisory GLSA 201006-20 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in Asterisk might allow remote attackers to cause
    a Denial of Service condition, or conduct other attacks." );
	script_tag( name: "solution", value: "All Asterisk users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.2.37'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201006-20" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=281107" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=283624" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=284892" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=295270" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201006-20." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "net-misc/asterisk", unaffected: make_list( "ge 1.2.37" ), vulnerable: make_list( "lt 1.2.37" ) ) ) != NULL){
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
