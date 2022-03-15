if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892665" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-21375" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-24 03:00:07 +0000 (Mon, 24 May 2021)" );
	script_name( "Debian LTS: Security Advisory for ring (DLA-2665-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2665-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2665-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ring'
  package(s) announced via the DLA-2665-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in ring, a secure and distributed voice, video and
chat platform. Actually the embedded copy of pjproject is affected by this
CVE.
Due to bad handling of two consecutive crafted answers to an INVITE, the
attacker is able to crash the server resulting in a denial of service." );
	script_tag( name: "affected", value: "'ring' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
20161221.2.7bd7d91~dfsg1-1+deb9u1.

We recommend that you upgrade your ring packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ring", ver: "20161221.2.7bd7d91~dfsg1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ring-daemon", ver: "20161221.2.7bd7d91~dfsg1-1+deb9u1", rls: "DEB9" ) )){
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

