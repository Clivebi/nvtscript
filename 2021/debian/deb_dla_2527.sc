if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892527" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2019-11840" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-18 00:15:00 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-18 04:00:06 +0000 (Mon, 18 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for snapd (DLA-2527-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2527-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'snapd'
  package(s) announced via the DLA-2527-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "golang-go.crypto was recently updated with a fix for CVE-2019-11840. This in
turn requires all packages that use the affected code to be recompiled in order
to pick up the security fix.

CVE-2019-11840

An issue was discovered in supplementary Go cryptography libraries, aka
golang-googlecode-go-crypto. If more than 256 GiB of keystream is
generated, or if the counter otherwise grows greater than 32 bits, the amd64
implementation will first generate incorrect output, and then cycle back to
previously generated keystream. Repeated keystream bytes can lead to loss of
confidentiality in encryption applications, or to predictability in CSPRNG
applications." );
	script_tag( name: "affected", value: "'snapd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2.21-2+deb9u1.

We recommend that you upgrade your snapd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-github-snapcore-snapd-dev", ver: "2.21-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-github-ubuntu-core-snappy-dev", ver: "2.21-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snap-confine", ver: "2.21-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snapd", ver: "2.21-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ubuntu-core-launcher", ver: "2.21-2+deb9u1", rls: "DEB9" ) )){
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

