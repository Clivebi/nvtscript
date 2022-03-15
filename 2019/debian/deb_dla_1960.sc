if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891960" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-16217", "CVE-2019-16218", "CVE-2019-16219", "CVE-2019-16220", "CVE-2019-16221", "CVE-2019-16222", "CVE-2019-16223" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-12 04:15:00 +0000 (Thu, 12 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-10-18 02:00:13 +0000 (Fri, 18 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-1960-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1960-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/939543" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-1960-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several cross-site scripting (XSS) vulnerabilities were discovered in
Wordpress, a popular content management framework. An attacker can use
these flaws to send malicious scripts to an unsuspecting user." );
	script_tag( name: "affected", value: "'wordpress' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.1.27+dfsg-0+deb8u1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.1.27+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1.27+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1.27+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1.27+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1.27+dfsg-0+deb8u1", rls: "DEB8" ) )){
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

