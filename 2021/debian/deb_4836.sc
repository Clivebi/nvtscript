if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704836" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2015-8011", "CVE-2020-27827" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-13 13:15:00 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-01-24 04:00:07 +0000 (Sun, 24 Jan 2021)" );
	script_name( "Debian: Security Advisory for openvswitch (DSA-4836-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4836.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4836-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvswitch'
  package(s) announced via the DSA-4836-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in the LLPD implementation of Open
vSwitch, a software-based Ethernet virtual switch, which could result in
denial of service." );
	script_tag( name: "affected", value: "'openvswitch' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.10.6+ds1-0+deb10u1.

We recommend that you upgrade your openvswitch packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-common", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-dbg", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-dev", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-pki", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-switch", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-testcontroller", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openvswitch-vtep", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ovn-central", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ovn-controller-vtep", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ovn-host", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-openvswitch", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-openvswitch", ver: "2.10.6+ds1-0+deb10u1", rls: "DEB10" ) )){
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

