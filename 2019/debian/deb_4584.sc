if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704584" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-11805", "CVE-2019-12420" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-13 19:15:00 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-12-15 03:00:06 +0000 (Sun, 15 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4584-1 (spamassassin - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4584.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4584-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spamassassin'
  package(s) announced via the DSA-4584-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in spamassassin, a Perl-based spam
filter using text analysis.

CVE-2018-11805
Malicious rule or configuration files, possibly downloaded from an
updates server, could execute arbitrary commands under multiple
scenarios.

CVE-2019-12420
Specially crafted multipart messages can cause spamassassin to use
excessive resources, resulting in a denial of service." );
	script_tag( name: "affected", value: "'spamassassin' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 3.4.2-1~deb9u2.

For the stable distribution (buster), these problems have been fixed in
version 3.4.2-1+deb10u1.

We recommend that you upgrade your spamassassin packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sa-compile", ver: "3.4.2-1~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-1~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamc", ver: "3.4.2-1~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sa-compile", ver: "3.4.2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamc", ver: "3.4.2-1+deb10u1", rls: "DEB10" ) )){
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
