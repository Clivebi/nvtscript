if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891747" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-5383" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for firmware-nonfree (DLA-1747-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1747-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firmware-nonfree'
  package(s) announced via the DLA-1747-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Eli Biham and Lior Neumann discovered a cryptographic weakness in the
Bluetooth LE SC pairing protocol, called the Fixed Coordinate Invalid
Curve Attack (CVE-2018-5383). Depending on the devices used, this
could be exploited by a nearby attacker to obtain sensitive
information, for denial of service, or for other security impact.

This flaw has been fixed in firmware for Intel Wireless 7260 (B3),
7260 (B5), 7265 (D1), and 8264 adapters, and for Qualcomm Atheros
QCA61x4 'ROME' version 3.2 adapters. Other Bluetooth adapters are
also affected and remain vulnerable." );
	script_tag( name: "affected", value: "'firmware-nonfree' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
20161130-5~deb8u1.

We recommend that you upgrade your firmware-nonfree packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "firmware-adi", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-atheros", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-bnx2", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-bnx2x", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-brcm80211", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-intelwimax", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-ipw2x00", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-ivtv", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-iwlwifi", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-libertas", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-linux", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-linux-nonfree", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-myricom", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-netxen", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-qlogic", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-ralink", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-realtek", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-samsung", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firmware-ti-connectivity", ver: "20161130-5~deb8u1", rls: "DEB8" ) )){
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

