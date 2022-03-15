if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891739" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-5418", "CVE-2019-5419" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 19:02:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for rails (DLA-1739-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00042.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1739-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924520" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rails'
  package(s) announced via the DLA-1739-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "John Hawthorn of Github discovered a file content disclosure
vulnerability in Rails, a ruby based web application framework.
Specially crafted accept headers in combination with calls to `render
file:` can cause arbitrary files on the target server to be rendered,
disclosing the file contents.

This vulnerability could also be exploited for a denial-of-service
attack." );
	script_tag( name: "affected", value: "'rails' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2:4.1.8-1+deb8u5.

We recommend that you upgrade your rails packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rails", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionmailer", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionpack", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-actionview", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activemodel", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activerecord", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activesupport", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-activesupport-2.3", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-rails", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-railties", ver: "2:4.1.8-1+deb8u5", rls: "DEB8" ) )){
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

