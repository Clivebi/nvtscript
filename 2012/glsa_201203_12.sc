if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71196" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027", "CVE-2012-0050" );
	script_version( "$Revision: 11859 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:35 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201203-12 (openssl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in OpenSSL, allowing
    remote attackers to cause a Denial of Service or obtain sensitive
    information." );
	script_tag( name: "solution", value: "All OpenSSL users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.0g'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-12" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=397695" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=399365" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201203-12." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-libs/openssl", unaffected: make_list( "ge 1.0.0g",
	 "rge 0.9.8t" ), vulnerable: make_list( "lt 1.0.0g" ) ) ) != NULL){
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

