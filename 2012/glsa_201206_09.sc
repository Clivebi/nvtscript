if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71576" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2787", "CVE-2010-2788", "CVE-2010-2789", "CVE-2011-0003", "CVE-2011-0047", "CVE-2011-0537", "CVE-2011-1579", "CVE-2011-1580", "CVE-2011-1766", "CVE-2012-1578", "CVE-2012-1579", "CVE-2012-1580", "CVE-2012-1581", "CVE-2012-1582" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:55 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-09 (MediaWiki)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in MediaWiki, the worst of
which leading to remote execution of arbitrary code." );
	script_tag( name: "solution", value: "All MediaWiki users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.18.2'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-09" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=366685" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=409513" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-09." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-apps/mediawiki", unaffected: make_list( "ge 1.18.2" ), vulnerable: make_list( "lt 1.18.2" ) ) ) != NULL){
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

