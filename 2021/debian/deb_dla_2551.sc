if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892551" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-7039", "CVE-2020-8608" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-14 03:50:00 +0000 (Sun, 14 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-10 04:00:18 +0000 (Wed, 10 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for slirp (DLA-2551-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2551-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2551-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'slirp'
  package(s) announced via the DLA-2551-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues have been found in slirp, a SLIP/PPP emulator using a dial up
shell account.

CVE-2020-7039

Due to mismanagement of memory, a heap-based buffer overflow or
other out-of-bounds access might happen, which can lead to a DoS
or potential execute arbitrary code.

CVE-2020-8608

Prevent a buffer overflow vulnerability due to incorrect usage
of return values from snprintf." );
	script_tag( name: "affected", value: "'slirp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:1.0.17-8+deb9u1.

We recommend that you upgrade your slirp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "slirp", ver: "1:1.0.17-8+deb9u1", rls: "DEB9" ) )){
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

