if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892504" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-15005", "CVE-2020-35477", "CVE-2020-35479", "CVE-2020-35480" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-27 04:15:00 +0000 (Sun, 27 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-23 04:00:14 +0000 (Wed, 23 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for mediawiki (DLA-2504-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00034.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2504-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediawiki'
  package(s) announced via the DLA-2504-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MediaWiki, a website engine
for collaborative work.

CVE-2020-15005

Private wikis behind a caching server using the img_auth.php image
authorization security feature may have had their files cached
publicly, so any unauthorized user could view them.

CVE-2020-35477

Blocks legitimate attempts to hide log entries in some situations.

CVE-2020-35479

Allows XSS via BlockLogFormatter.php. Language::translateBlockExpiry
itself does not escape in all code paths. For example, the return of
Language::userTimeAndDate is always unsafe for HTML in a month
value.

CVE-2020-35480

Missing users (accounts that don't exist) and hidden users (accounts
that have been explicitly hidden due to being abusive, or similar)
that the viewer cannot see are handled differently, exposing
sensitive information about the hidden status to unprivileged
viewers." );
	script_tag( name: "affected", value: "'mediawiki' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:1.27.7-1~deb9u7.

We recommend that you upgrade your mediawiki packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mediawiki", ver: "1:1.27.7-1~deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mediawiki-classes", ver: "1:1.27.7-1~deb9u7", rls: "DEB9" ) )){
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
exit( 0 );

