if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71187" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3564", "CVE-2010-0156", "CVE-2011-3848", "CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871", "CVE-2011-3872", "CVE-2012-1053", "CVE-2012-1054" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:35 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-03 (puppet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in Puppet, the worst of
    which might allow local attackers to gain escalated privileges." );
	script_tag( name: "solution", value: "All Puppet users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-admin/puppet-2.7.11'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=303729" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=308031" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=384859" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=385149" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=388161" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=403963" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-admin/puppet", unaffected: make_list( "ge 2.7.11" ), vulnerable: make_list( "lt 2.7.11" ) ) ) != NULL){
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

