if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72420" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1398", "CVE-2011-3379", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0788", "CVE-2012-0789", "CVE-2012-0830", "CVE-2012-0831", "CVE-2012-1172", "CVE-2012-1823", "CVE-2012-2143", "CVE-2012-2311", "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-2386", "CVE-2012-2688", "CVE-2012-3365", "CVE-2012-3450" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-26 11:20:48 -0400 (Wed, 26 Sep 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201209-03 (php)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in PHP, the worst of which lead
to remote execution of arbitrary code." );
	script_tag( name: "solution", value: "All PHP users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.3.15'


All PHP users on ARM should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.4.5'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=384301" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=396311" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=396533" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=399247" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=399567" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=399573" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=401997" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=410957" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=414553" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=421489" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=427354" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=429630" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201209-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-lang/php", unaffected: make_list( "ge 5.3.15",
	 "ge 5.4.5" ), vulnerable: make_list( "lt 5.3.15",
	 "lt 5.4.5" ) ) ) != NULL){
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

