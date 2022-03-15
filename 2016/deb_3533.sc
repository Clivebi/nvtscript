if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703533" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_cve_id( "CVE-2016-2074" );
	script_name( "Debian Security Advisory DSA 3533-1 (openvswitch - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-29 00:00:00 +0200 (Tue, 29 Mar 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-23 01:29:00 +0000 (Fri, 23 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3533.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openvswitch on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 2.3.0+git20140819-3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.0+git20140819-4.

We recommend that you upgrade your openvswitch packages." );
	script_tag( name: "summary", value: "Kashyap Thimmaraju and Bhargava Shastry
discovered a remotely triggerable buffer overflow vulnerability in openvswitch,
a production quality, multilayer virtual switch implementation. Specially crafted
MPLS packets could overflow the buffer reserved for MPLS labels in an
OVS internal data structure. A remote attacker can take advantage of
this flaw to cause a denial of service, or potentially, execution of
arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openvswitch-common", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvswitch-dbg", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvswitch-ipsec", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvswitch-pki", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvswitch-switch", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvswitch-test", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openvswitch-vtep", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-openvswitch", ver: "2.3.0+git20140819-3+deb8u1", rls: "DEB8" ) ) != NULL){
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

