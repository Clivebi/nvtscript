if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892145" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-10108", "CVE-2020-10109" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-03-18 10:44:58 +0000 (Wed, 18 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for twisted (DLA-2145-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2145-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/953950" );
	script_xref( name: "URL", value: "https://know.bishopfox.com/advisories/twisted-version-19.10.0#INOR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'twisted'
  package(s) announced via the DLA-2145-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were a number of HTTP request splitting
vulnerabilities in Twisted, an Python event-based framework for
building various types of internet applications.

For more information, please see the referenced advisories." );
	script_tag( name: "affected", value: "'twisted' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in twisted
version 14.0.2-3+deb8u1.

We recommend that you upgrade your twisted packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-twisted", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-bin", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-bin-dbg", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-conch", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-core", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-lore", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-mail", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-names", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-news", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-runner", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-runner-dbg", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-web", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-twisted-words", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "twisted-doc", ver: "14.0.2-3+deb8u1", rls: "DEB8" ) )){
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

