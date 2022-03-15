if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891845" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-12594", "CVE-2019-7165" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-08 02:00:08 +0000 (Mon, 08 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for dosbox (DLA-1845-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1845-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/931222" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dosbox'
  package(s) announced via the DLA-1845-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities were discovered in DOSBox, an
emulator for running old DOS programs.

CVE-2019-7165

A very long line inside a bat file would overflow the parsing buffer
which could be used by an attacker to execute arbitrary code.

CVE-2019-12594

Insufficient access controls inside DOSBox allowed attackers to
access resources on the host system and execute arbitrary code." );
	script_tag( name: "affected", value: "'dosbox' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.74-4+deb8u1.

We recommend that you upgrade your dosbox packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dosbox", ver: "0.74-4+deb8u1", rls: "DEB8" ) )){
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

