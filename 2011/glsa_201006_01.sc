if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69004" );
	script_version( "$Revision: 14171 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-1861", "CVE-2007-2754" );
	script_name( "Gentoo Security Advisory GLSA 201006-01 (freetype)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in FreeType might result in the remote execution
    of arbitrary code." );
	script_tag( name: "solution", value: "All FreeType 1 users should upgrade to an unaffected version:

# emerge --sync
# emerge --ask --oneshot --verbose '>=media-libs/freetype-1.4_pre20080316-r2'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201006-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=271234" );
	script_xref( name: "URL", value: "http://www.gentoo.org/security/en/glsa/glsa-200607-02.xml" );
	script_xref( name: "URL", value: "http://www.gentoo.org/security/en/glsa/glsa-200705-22.xml" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201006-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "media-libs/freetype", unaffected: make_list( "ge 1.4_pre20080316-r2" ), vulnerable: make_list( "lt 1.4_pre20080316-r2" ) ) ) != NULL){
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

