if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892423" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903", "CVE-2019-12295" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:00:14 +0000 (Tue, 03 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for wireshark (DLA-2423-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00036.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2423-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/926718" );
	script_xref( name: "URL", value: "https://bugs.debian.org/929446" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the DLA-2423-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were fixed in the Wireshark network
protocol analyzer.

CVE-2019-10894

GSS-API dissector crash

CVE-2019-10895

NetScaler file parser crash

CVE-2019-10896

DOF dissector crash

CVE-2019-10899

SRVLOC dissector crash

CVE-2019-10901

LDSS dissector crash

CVE-2019-10903

DCERPC SPOOLSS dissector crash

CVE-2019-12295

Dissection engine could crash" );
	script_tag( name: "affected", value: "'wireshark' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.6.8-1.1~deb9u1.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libwireshark-data", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwireshark11", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwiretap8", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwscodecs2", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwsutil9", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tshark", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-common", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-dev", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-doc", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-gtk", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-qt", ver: "2.6.8-1.1~deb9u1", rls: "DEB9" ) )){
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

