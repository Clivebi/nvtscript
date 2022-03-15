if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70766" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2761", "CVE-2010-3172", "CVE-2010-3764", "CVE-2010-4411", "CVE-2010-4567", "CVE-2010-4568", "CVE-2010-4569", "CVE-2010-4570", "CVE-2010-4572", "CVE-2011-0046", "CVE-2011-0048", "CVE-2011-2379", "CVE-2011-2380", "CVE-2011-2381", "CVE-2011-2976", "CVE-2011-2977", "CVE-2011-2978", "CVE-2011-2979" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 10:04:39 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201110-03 (bugzilla)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in Bugzilla, the worst of which
    leading to privilege escalation." );
	script_tag( name: "solution", value: "All Bugzilla users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/bugzilla-3.6.6'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since August 27, 2011. It is likely that your system is
already
      no longer affected by this issue." );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=352781" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=380255" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=386203" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201110-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-apps/bugzilla", unaffected: make_list( "ge 3.6.6" ), vulnerable: make_list( "lt 3.6.6" ) ) ) != NULL){
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

