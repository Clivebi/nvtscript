if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704558" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-8625", "CVE-2019-8720", "CVE-2019-8769", "CVE-2019-8771" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-15 07:15:00 +0000 (Sun, 15 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-11-06 03:00:08 +0000 (Wed, 06 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4558-1 (webkit2gtk - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4558.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4558-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk'
  package(s) announced via the DSA-4558-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the webkit2gtk web engine:

CVE-2019-8625
Sergei Glazunov discovered that maliciously crafted web content
may lead to universal cross site scripting.

CVE-2019-8720
Wen Xu discovered that maliciously crafted web content may lead to
arbitrary code execution.

CVE-2019-8769
Pierre Reimertz discovered that visiting a maliciously crafted
website may reveal browsing history.

CVE-2019-8771
Eliya Stein discovered that maliciously crafted web content may
violate iframe sandboxing policy." );
	script_tag( name: "affected", value: "'webkit2gtk' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.26.1-3~deb10u1.

We recommend that you upgrade your webkit2gtk packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-javascriptcoregtk-4.0", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-webkit2-4.0", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-18", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-bin", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjavascriptcoregtk-4.0-dev", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-37-gtk2", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-dev", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwebkit2gtk-4.0-doc", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "webkit2gtk-driver", ver: "2.26.1-3~deb10u1", rls: "DEB10" ) )){
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

