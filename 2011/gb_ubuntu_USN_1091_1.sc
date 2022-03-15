if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1091-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840617" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-25 15:26:27 +0100 (Fri, 25 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1091-1" );
	script_name( "Ubuntu Update for Firefox and Xulrunner vulnerabilities USN-1091-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|10\\.10|10\\.04 LTS|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1091-1" );
	script_tag( name: "affected", value: "Firefox and Xulrunner vulnerabilities on Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that several invalid HTTPS certificates were issued and
  revoked. An attacker could use these to perform a man-in-the-middle attack.
  These were placed on the certificate blacklist to prevent their misuse." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "abrowser-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dbg", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-gnome-support", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.5-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-dom-inspector", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-libthai", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.1-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.1-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.0-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.0", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.1-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.1", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.5", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-dom-inspector", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-venkman", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.1-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.1-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.1", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dom-inspector", ver: "3.6.16+build1+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "firefox-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dbg", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-mozsymbols", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-gnome-support", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.10.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-mozsymbols", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dbg", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-gnome-support", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.5-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser-3.5", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-dom-inspector", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2-libthai", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-2", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.5", ver: "3.6.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "abrowser-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-branding", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support-dbg", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dbg", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-gnome-support", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.2-testsuite", ver: "1.9.2.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "abrowser", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-3.0", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-granparadiso-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-trunk-dev", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-granparadiso-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-granparadiso", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-libthai", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-trunk-gnome-support", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "firefox-trunk", ver: "3.6.16+build1+nobinonly-0ubuntu0.8.04.1", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

