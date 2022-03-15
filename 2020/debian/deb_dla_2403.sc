if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892403" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-15169" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-08 18:58:00 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-10-10 03:00:07 +0000 (Sat, 10 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for rails (DLA-2403-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2403-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/970040" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rails'
  package(s) announced via the DLA-2403-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A potential Cross-Site Scripting (XSS) vulnerability was found in rails,
a ruby based MVC framework. Views that allow the user to control the
default (not found) value of the `t` and `translate` helpers could be
susceptible to XSS attacks. When an HTML-unsafe string is passed as the
default for a missing translation key named html or ending in _html, the
default string is incorrectly marked as HTML-safe and not escaped." );
	script_tag( name: "affected", value: "'rails' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2:4.2.7.1-1+deb9u4.

We recommend that you upgrade your rails packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rails", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionmailer", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionpack", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionview", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activejob", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activemodel", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activerecord", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activesupport", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-rails", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-railties", ver: "2:4.2.7.1-1+deb9u4", rls: "DEB9" ) )){
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

