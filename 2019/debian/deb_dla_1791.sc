if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891791" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2018-20194", "CVE-2018-20197", "CVE-2018-20198", "CVE-2018-20362" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-15 18:15:00 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "creation_date", value: "2019-05-19 02:00:08 +0000 (Sun, 19 May 2019)" );
	script_name( "Debian LTS: Security Advisory for faad2 (DLA-1791-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1791-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'faad2'
  package(s) announced via the DLA-1791-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in faad2, the Freeware Advanced Audio
Coder:

CVE-2018-20194
CVE-2018-20197

    Improper handling of implicit channel mapping reconfiguration leads to
    multiple heap based buffer overflow issues. These flaws might be leveraged
    by remote attackers to cause DoS.

CVE-2018-20198
CVE-2018-20362

    Insufficient user input validation in the sbr_hfadj module leads to
    stack-based buffer underflow issues. These flaws might be leveraged by
    remote attackers to cause DoS or any other unspecified impact." );
	script_tag( name: "affected", value: "'faad2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.7-8+deb8u2.

We recommend that you upgrade your faad2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "faad", ver: "2.7-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "faad2-dbg", ver: "2.7-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfaad-dev", ver: "2.7-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfaad2", ver: "2.7-8+deb8u2", rls: "DEB8" ) )){
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

