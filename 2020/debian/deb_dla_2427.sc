if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892427" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-14355" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:00:17 +0000 (Tue, 03 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for spice (DLA-2427-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2427-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/971750" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice'
  package(s) announced via the DLA-2427-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple buffer overflow vulnerabilities were found in the QUIC
image decoding process of the SPICE remote display system,
before spice-0.14.2-1.

Both the SPICE client (spice-gtk) and server are affected by
these flaws. These flaws allow a malicious client or server to
send specially crafted messages that, when processed by the
QUIC image compression algorithm, result in a process crash
or potential code execution." );
	script_tag( name: "affected", value: "'spice' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.12.8-2.1+deb9u4.

We recommend that you upgrade your spice packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libspice-server-dev", ver: "0.12.8-2.1+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspice-server1", ver: "0.12.8-2.1+deb9u4", rls: "DEB9" ) )){
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

