if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69036" );
	script_cve_id( "CVE-2010-4574", "CVE-2010-4575", "CVE-2010-4576", "CVE-2010-4577", "CVE-2010-4578" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-07-31T07:11:31+0000" );
	script_tag( name: "last_modification", value: "2020-07-31 07:11:31 +0000 (Fri, 31 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_name( "Gentoo Security Advisory GLSA 201012-01 (chromium)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been reported in Chromium, some of which may
    allow user-assisted execution of arbitrary code." );
	script_tag( name: "solution", value: "All Chromium users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/chromium-8.0.552.224'" );
	script_xref( name: "URL", value: "http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201012-01" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=325451" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=326717" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=330003" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=333559" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=335750" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=338204" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=341797" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=344201" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=347625" );
	script_xref( name: "URL", value: "http://bugs.gentoo.org/show_bug.cgi?id=348651" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/06/stable-channel-update_24.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/07/stable-channel-update.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/07/stable-channel-update_26.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/08/stable-channel-update_19.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_14.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_17.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/10/stable-channel-update.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/11/stable-channel-update.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates_13.html" );
	script_tag( name: "summary", value: "The remote host is missing updates announced in
advisory GLSA 201012-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-gentoo.inc.sc");
require("revisions-lib.inc.sc");
res = "";
report = "";
report = "";
if(( res = ispkgvuln( pkg: "www-client/chromium", unaffected: make_list( "ge 8.0.552.224" ), vulnerable: make_list( "lt 8.0.552.224" ) ) ) != NULL){
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

