if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69029" );
	script_version( "$Revision: 14171 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3953", "CVE-2009-4324", "CVE-2010-0186", "CVE-2010-0188", "CVE-2010-0190", "CVE-2010-0191", "CVE-2010-0192", "CVE-2010-0193", "CVE-2010-0194", "CVE-2010-0195", "CVE-2010-0196", "CVE-2010-0197", "CVE-2010-0198", "CVE-2010-0199", "CVE-2010-0201", "CVE-2010-0202", "CVE-2010-0203", "CVE-2010-0204", "CVE-2010-1241", "CVE-2010-1285", "CVE-2010-1295", "CVE-2010-1297", "CVE-2010-2168", "CVE-2010-2201", "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205", "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209", "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212" );
	script_name( "Gentoo Security Advisory GLSA 201009-05 (acroread)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities in Adobe Reader might result in the execution of
    arbitrary code or other attacks." );
	script_tag( name: "solution", value: "All Adobe Reader users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-9.3.4'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201009-05" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=297385" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=306429" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=313343" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=322857" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa10-01.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-02.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-07.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-09.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-14.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-16.html" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201009-05." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "app-text/acroread", unaffected: make_list( "ge 9.3.4" ), vulnerable: make_list( "lt 9.3.4" ) ) ) != NULL){
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

