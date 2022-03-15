if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71313" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3066", "CVE-2011-3067", "CVE-2011-3068", "CVE-2011-3069", "CVE-2011-3070", "CVE-2011-3071", "CVE-2011-3072", "CVE-2011-3073", "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3076", "CVE-2011-3077" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Gentoo Security Advisory GLSA 201204-03 (chromium)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been reported in Chromium, some of
    which may allow execution of arbitrary code." );
	script_tag( name: "solution", value: "All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-18.0.1025.151'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201204-03" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=410963" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2012/04/stable-and-beta-channel-updates.html" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201204-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "www-client/chromium", unaffected: make_list( "ge 18.0.1025.151" ), vulnerable: make_list( "lt 18.0.1025.151" ) ) ) != NULL){
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

