if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704457" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-15587" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-10 07:29:00 +0000 (Mon, 10 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-08 02:00:06 +0000 (Sat, 08 Jun 2019)" );
	script_name( "Debian Security Advisory DSA 4457-1 (evolution - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4457.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4457-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evolution'
  package(s) announced via the DSA-4457-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Hanno Boeck discovered that Evolution was vulnerable to OpenPGP
signatures being spoofed for arbitrary messages using a specially
crafted HTML email. This issue was mitigated by moving the security
bar with encryption and signature information above the message
headers." );
	script_tag( name: "affected", value: "'evolution' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 3.22.6-1+deb9u2.

We recommend that you upgrade your evolution packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "evolution", ver: "3.22.6-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-common", ver: "3.22.6-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-dev", ver: "3.22.6-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-plugins", ver: "3.22.6-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "evolution-plugins-experimental", ver: "3.22.6-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libevolution", ver: "3.22.6-1+deb9u2", rls: "DEB9" ) )){
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

