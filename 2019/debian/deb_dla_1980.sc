if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891980" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-17669", "CVE-2019-17670", "CVE-2019-17671", "CVE-2019-17675" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-05 19:15:00 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-06 03:00:18 +0000 (Wed, 06 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-1980-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1980-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942459" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-1980-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities in wordpress, a web blogging tool, have been
fixed.

CVE-2019-17669

Server Side Request Forgery (SSRF) vulnerability because URL
validation does not consider the interpretation of a name as a
series of hex characters.

CVE-2019-17670

Server Side Request Forgery (SSRF) vulnerability was reported in
wp_validate_redirect(). Normalize the path when validating the
location for relative URLs.

CVE-2019-17671

Unauthenticated viewing of certain content (private or draft posts)
is possible because the static query property is mishandled.

CVE-2019-17675

Wordpress does not properly consider type confusion during
validation of the referer in the admin pages. This vulnerability
affects the check_admin_referer() WordPress function." );
	script_tag( name: "affected", value: "'wordpress' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.1.28+dfsg-0+deb8u1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.1.28+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1.28+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1.28+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1.28+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1.28+dfsg-0+deb8u1", rls: "DEB8" ) )){
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

