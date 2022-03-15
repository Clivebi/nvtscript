if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891772" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2016-10746" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-01 19:47:00 +0000 (Wed, 01 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-01 02:00:09 +0000 (Wed, 01 May 2019)" );
	script_name( "Debian LTS: Security Advisory for libvirt (DLA-1772-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00032.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1772-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the DLA-1772-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libvirt-domain.c in libvirt supports virDomainGetTime API calls by guest agents
with an RO connection, even though an RW connection was supposed to be
required. This could lead to could lead to potentially disclosing unintended
information or denial of service by causing libvirt to block." );
	script_tag( name: "affected", value: "'libvirt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.2.9-9+deb8u6.

We recommend that you upgrade your libvirt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-clients", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-dev", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-doc", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-sanlock", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "1.2.9-9+deb8u6", rls: "DEB8" ) )){
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

