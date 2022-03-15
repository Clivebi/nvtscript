if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71317" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-2445", "CVE-2011-2450", "CVE-2011-2451", "CVE-2011-2452", "CVE-2011-2453", "CVE-2011-2454", "CVE-2011-2455", "CVE-2011-2456", "CVE-2011-2457", "CVE-2011-2458", "CVE-2011-2459", "CVE-2011-2460", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754", "CVE-2012-0755", "CVE-2012-0756", "CVE-2012-0767", "CVE-2012-0768", "CVE-2012-0769", "CVE-2012-0773" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:58 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201204-07 (Adobe Flash Player)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in Adobe Flash Player, the worst of which
    might allow remote attackers to execute arbitrary code." );
	script_tag( name: "solution", value: "All Adobe Flash Player users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-11.2.202.228'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201204-07" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=390149" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=404101" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=407023" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=410005" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201204-07." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-plugins/adobe-flash", unaffected: make_list( "ge 11.2.202.228" ), vulnerable: make_list( "lt 11.2.202.228" ) ) ) != NULL){
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

