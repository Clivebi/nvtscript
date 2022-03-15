if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892178" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-11728", "CVE-2020-11729" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-18 03:00:07 +0000 (Sat, 18 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for awl (DLA-2178-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2178-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/956650" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'awl'
  package(s) announced via the DLA-2178-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Following CVEs were reported against the awl source package:

CVE-2020-11728

An issue was discovered in DAViCal Andrew's Web Libraries (AWL)
through 0.60. Session management does not use a sufficiently
hard-to-guess session key. Anyone who can guess the microsecond
time (and the incrementing session_id) can impersonate a session.

CVE-2020-11729

An issue was discovered in DAViCal Andrew's Web Libraries (AWL)
through 0.60. Long-term session cookies, uses to provide
long-term session continuity, are not generated securely, enabling
a brute-force attack that may be successful." );
	script_tag( name: "affected", value: "'awl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.55-1+deb8u1.

We recommend that you upgrade your awl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "awl-doc", ver: "0.55-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libawl-php", ver: "0.55-1+deb8u1", rls: "DEB8" ) )){
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

