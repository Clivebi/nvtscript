if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704677" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2019-16217", "CVE-2019-16218", "CVE-2019-16219", "CVE-2019-16220", "CVE-2019-16221", "CVE-2019-16222", "CVE-2019-16223", "CVE-2019-16780", "CVE-2019-16781", "CVE-2019-17669", "CVE-2019-17671", "CVE-2019-17672", "CVE-2019-17673", "CVE-2019-17674", "CVE-2019-17675", "CVE-2019-20041", "CVE-2019-20042", "CVE-2019-20043", "CVE-2019-9787", "CVE-2020-11025", "CVE-2020-11026", "CVE-2020-11027", "CVE-2020-11028", "CVE-2020-11029", "CVE-2020-11030" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-05 19:15:00 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2020-05-07 03:00:28 +0000 (Thu, 07 May 2020)" );
	script_name( "Debian: Security Advisory for wordpress (DSA-4677-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4677.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4677-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the DSA-4677-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They allowed remote attackers to perform various Cross-Side
Scripting (XSS) and Cross-Site Request Forgery (CSRF) attacks, create
files on the server, disclose private information, create open
redirects, poison cache, and bypass authorization access and input
sanitation." );
	script_tag( name: "affected", value: "'wordpress' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 4.7.5+dfsg-2+deb9u6.

For the stable distribution (buster), these problems have been fixed in
version 5.0.4+dfsg1-1+deb10u2.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.7.5+dfsg-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.7.5+dfsg-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.7.5+dfsg-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyseventeen", ver: "4.7.5+dfsg-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentysixteen", ver: "4.7.5+dfsg-2+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "5.0.4+dfsg1-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "5.0.4+dfsg1-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentynineteen", ver: "5.0.4+dfsg1-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyseventeen", ver: "5.0.4+dfsg1-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentysixteen", ver: "5.0.4+dfsg1-1+deb10u2", rls: "DEB10" ) )){
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

