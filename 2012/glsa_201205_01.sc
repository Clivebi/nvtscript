if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71387" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3078", "CVE-2011-3081", "CVE-2012-1521" );
	script_version( "2020-04-16T06:32:08+0000" );
	script_tag( name: "last_modification", value: "2020-04-16 06:32:08 +0000 (Thu, 16 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-05-31 11:54:20 -0400 (Thu, 31 May 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201205-01 (chromium)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been reported in Chromium, some of
    which may allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-18.0.1025.168'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201205-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=414199" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2012/04/stable-channel-update_30.html" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201205-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-client/chromium", unaffected: make_list( "ge 18.0.1025.168" ), vulnerable: make_list( "lt 18.0.1025.168" ) ) ) != NULL){
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

