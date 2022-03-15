if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71852" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988", "CVE-2012-1989" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:52 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201208-02 (Puppet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Puppet, the worst of
    which could lead to execution of arbitrary code." );
	script_tag( name: "solution", value: "All Puppet users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-admin/puppet-2.7.13'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201208-02" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=410857" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201208-02." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-admin/puppet", unaffected: make_list( "ge 2.7.13" ), vulnerable: make_list( "lt 2.7.13" ) ) ) != NULL){
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

