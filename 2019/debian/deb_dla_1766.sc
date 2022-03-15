if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891766" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2018-15587" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-10 07:29:00 +0000 (Mon, 10 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-27 02:00:06 +0000 (Sat, 27 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for evolution (DLA-1766-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1766-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924616" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evolution'
  package(s) announced via the DLA-1766-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Hanno Boeck discovered that GNOME Evolution is prone to OpenPGP
signatures being spoofed for arbitrary messages using a specially
crafted HTML email. This issue was mitigated by moving the security
bar with encryption and signature information above the message headers." );
	script_tag( name: "affected", value: "'evolution' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.12.9~git20141130.241663-1+deb8u1.

We recommend that you upgrade your evolution packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "evolution", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-common", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-dbg", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-dev", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-plugins", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-plugins-experimental", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libevolution", ver: "3.12.9~git20141130.241663-1+deb8u1", rls: "DEB8" ) )){
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

