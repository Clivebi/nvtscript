if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71545" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3615", "CVE-2010-3762", "CVE-2011-0414", "CVE-2011-1910", "CVE-2011-2464", "CVE-2011-2465", "CVE-2011-4313" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:52 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201206-01 (bind)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in BIND, the worst of
    which allowing to cause remote Denial of Service." );
	script_tag( name: "solution", value: "All bind users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-dns/bind-9.7.4_p1'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since December 22, 2011. It is likely that your system is
      already no longer affected by this issue." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=347621" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=356223" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=368863" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=374201" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=374623" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=390753" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201206-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-dns/bind", unaffected: make_list( "ge 9.7.4_p1" ), vulnerable: make_list( "lt 9.7.4_p1" ) ) ) != NULL){
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

