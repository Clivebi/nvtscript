if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71551" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2010-0408", "CVE-2010-0434", "CVE-2010-1452", "CVE-2010-2791", "CVE-2011-3192", "CVE-2011-3348", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0883" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:53 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-25 (apache)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in Apache HTTP Server." );
	script_tag( name: "solution", value: "All Apache HTTP Server users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/apache-2.2.22-r1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-25" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=308049" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=330195" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=380475" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=382971" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=385859" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=389353" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=392189" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=398761" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=401081" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=412481" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-25." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-servers/apache", unaffected: make_list( "ge 2.2.22-r1" ), vulnerable: make_list( "lt 2.2.22-r1" ) ) ) != NULL){
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

