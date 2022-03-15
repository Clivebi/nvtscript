if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704723" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-11739", "CVE-2020-11740", "CVE-2020-11741", "CVE-2020-11742", "CVE-2020-11743", "CVE-2020-15563", "CVE-2020-15564", "CVE-2020-15565", "CVE-2020-15566", "CVE-2020-15567" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-13 16:15:00 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-14 03:00:27 +0000 (Tue, 14 Jul 2020)" );
	script_name( "Debian: Security Advisory for xen (DSA-4723-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4723.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4723-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the DSA-4723-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor,
which could result in denial of service, guest-to-host privilege
escalation or information leaks." );
	script_tag( name: "affected", value: "'xen' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 4.11.4+24-gddaaccbbab-1~deb10u1.

We recommend that you upgrade your xen packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxencall1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxendevicemodel1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenevtchn1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenforeignmemory1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxengnttab1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenmisc4.11", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxentoolcore1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxentoollog1", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-doc", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.11-amd64", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.11-arm64", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.11-armhf", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-common", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.11", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.11.4+24-gddaaccbbab-1~deb10u1", rls: "DEB10" ) )){
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

