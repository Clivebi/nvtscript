if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704193" );
	script_version( "2021-06-17T04:16:32+0000" );
	script_cve_id( "CVE-2018-10100", "CVE-2018-10101", "CVE-2018-10102" );
	script_name( "Debian Security Advisory DSA 4193-1 (wordpress - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-05 00:00:00 +0200 (Sat, 05 May 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 13:49:00 +0000 (Fri, 18 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4193.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 4.1+dfsg-1+deb8u17.

For the stable distribution (stretch), these problems have been fixed in
version 4.7.5+dfsg-2+deb9u3.

We recommend that you upgrade your wordpress packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/wordpress" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in wordpress, a web blogging
tool, which could allow remote attackers to compromise a site via
cross-site scripting, bypass restrictions or unsafe redirects." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.7.5+dfsg-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.7.5+dfsg-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.7.5+dfsg-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyseventeen", ver: "4.7.5+dfsg-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentysixteen", ver: "4.7.5+dfsg-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.1+dfsg-1+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1+dfsg-1+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1+dfsg-1+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1+dfsg-1+deb8u17", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1+dfsg-1+deb8u17", rls: "DEB8" ) )){
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

