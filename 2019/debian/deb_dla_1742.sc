if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891742" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-8942", "CVE-2019-9787" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-31 22:29:00 +0000 (Sun, 31 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-1742-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00044.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1742-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924546" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-1742-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Simon Scannell of Ripstech Technologies discovered multiple
vulnerabilities in wordpress, a web blogging manager.

CVE-2019-8942

remote code execution in wordpress because an _wp_attached_file Post
Meta entry can be changed to an arbitrary string, such as one ending
with a .jpg?file.php substring. An attacker with author privileges
can execute arbitrary code by uploading a crafted image containing
PHP code in the Exif metadata.

CVE-2019-9787

wordpress does not properly filter comment content, leading to
Remote Code Execution by unauthenticated users in a default
configuration. This occurs because CSRF protection is mishandled,
and because Search Engine Optimization of A elements is performed
incorrectly, leading to XSS. The XSS results in administrative
access." );
	script_tag( name: "affected", value: "'wordpress' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.1.26+dfsg-1+deb8u1.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.1.26+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1.26+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1.26+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1.26+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1.26+dfsg-1+deb8u1", rls: "DEB8" ) )){
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

