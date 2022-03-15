if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71388" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2320", "CVE-2012-2321", "CVE-2012-2322" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:54:20 -0400 (Thu, 31 May 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201205-02 (ConnMan)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in ConnMan, allowing
    attackers to execute arbitrary code or cause Denial of Service." );
	script_tag( name: "solution", value: "All ConnMan users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/connman-1.0-r1'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201205-02" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=415415" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201205-02." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-misc/connman", unaffected: make_list( "ge 1.0-r1" ), vulnerable: make_list( "lt 1.0-r1" ) ) ) != NULL){
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
