if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704517" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-15846" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-07 02:00:05 +0000 (Sat, 07 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4517-1 (exim4 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4517.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4517-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim4'
  package(s) announced via the DSA-4517-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "'Zerons' and Qualys discovered that a buffer overflow triggerable in the
TLS negotiation code of the Exim mail transport agent could result in the
execution of arbitrary code with root privileges." );
	script_tag( name: "affected", value: "'exim4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 4.89-2+deb9u6.

For the stable distribution (buster), this problem has been fixed in
version 4.92-8+deb10u2.

We recommend that you upgrade your exim4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exim4", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-base", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-config", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eximon4", ver: "4.92-8+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-base", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-config", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eximon4", ver: "4.89-2+deb9u6", rls: "DEB9" ) )){
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

