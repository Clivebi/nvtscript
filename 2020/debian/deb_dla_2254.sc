if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892254" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-14929" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-03 04:15:00 +0000 (Fri, 03 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-26 03:00:06 +0000 (Fri, 26 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for alpine (DLA-2254-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2254-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/963179" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'alpine'
  package(s) announced via the DLA-2254-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2020-14929

Alpine before 2.23 silently proceeds to use an insecure connection
after a /tls is sent in certain circumstances involving PREAUTH, which
is a less secure behavior than the alternative of closing the connection
and letting the user decide what they would like to do." );
	script_tag( name: "affected", value: "'alpine' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.11+dfsg1-3+deb8u1.

We recommend that you upgrade your alpine packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "alpine", ver: "2.11+dfsg1-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "alpine-dbg", ver: "2.11+dfsg1-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "alpine-doc", ver: "2.11+dfsg1-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "alpine-pico", ver: "2.11+dfsg1-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pilot", ver: "2.11+dfsg1-3+deb8u1", rls: "DEB8" ) )){
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

