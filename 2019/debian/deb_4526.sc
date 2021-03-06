if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704526" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-16378" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 05:15:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-09-20 02:00:08 +0000 (Fri, 20 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4526-1 (opendmarc - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4526.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4526-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opendmarc'
  package(s) announced via the DSA-4526-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenDMARC, a milter implementation of DMARC, is
prone to a signature-bypass vulnerability with multiple From: addresses." );
	script_tag( name: "affected", value: "'opendmarc' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.3.2-2+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 1.3.2-6+deb10u1.

We recommend that you upgrade your opendmarc packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopendmarc-dev", ver: "1.3.2-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopendmarc2", ver: "1.3.2-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "opendmarc", ver: "1.3.2-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopendmarc-dev", ver: "1.3.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopendmarc2", ver: "1.3.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "opendmarc", ver: "1.3.2-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rddmarc", ver: "1.3.2-2+deb9u2", rls: "DEB9" ) )){
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

