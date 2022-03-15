if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891832" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-10161", "CVE-2019-10167" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-25 14:09:00 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "creation_date", value: "2019-06-25 02:00:09 +0000 (Tue, 25 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for libvirt (DLA-1832-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1832-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the DLA-1832-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in libvirt, an abstraction API
for different underlying virtualisation mechanisms provided by the
kernel, etc.

  * CVE-2019-10161: Prevent a vulnerability where readonly clients
could use the API to specify an arbitrary path which would be
accessed with the permissions of the libvirtd process. An attacker
with access to the libvirtd socket could use this to probe the
existence of arbitrary files, cause a denial of service or
otherwise cause libvirtd to execute arbitrary programs.

  * CVE-2019-10167: Prevent an arbitrary code execution vulnerability
via the API where a user-specified binary used to probe the
domain's capabilities. read-only clients could specify an
arbitrary path for this argument, causing libvirtd to execute a
crafted executable with its own privileges." );
	script_tag( name: "affected", value: "'libvirt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in libvirt
version 1.2.9-9+deb8u7.

We recommend that you upgrade your libvirt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-clients", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-dev", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-doc", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-sanlock", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "1.2.9-9+deb8u7", rls: "DEB8" ) )){
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

