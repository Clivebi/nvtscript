if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842213" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-09 11:06:47 +0200 (Tue, 09 Jun 2015)" );
	script_cve_id( "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1260", "CVE-2015-1262", "CVE-2015-1265", "CVE-2015-3910" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-2610-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Several security issues were discovered
in the DOM implementation in Blink. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
bypass Same Origin Policy restrictions. (CVE-2015-1253, CVE-2015-1254)

A use-after-free was discovered in the WebAudio implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via renderer crash, or execute arbitrary code with the privileges
of the sandboxed render process. (CVE-2015-1255)

A use-after-free was discovered in the SVG implementation in Blink. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash, or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2015-1256)

A security issue was discovered in the SVG implementation in Blink. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash. (CVE-2015-1257)

An issue was discovered with the build of libvpx. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or execute
arbitrary code with the privileges of the sandboxed render process.
(CVE-2015-1258)

Multiple use-after-free issues were discovered in the WebRTC
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via renderer crash, or execute arbitrary code
with the privileges of the sandboxed render process. (CVE-2015-1260)

An uninitialized value bug was discovered in the font shaping code in
Blink. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of service
via renderer crash. (CVE-2015-1262)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1265)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit these to read uninitialized memory, cause a denial of service via
renderer crash or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2015-3910)" );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 14.10,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2610-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2610-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.7.8-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.7.8-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs:amd64", ver: "1.7.8-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs:i386", ver: "1.7.8-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs-extra:amd64", ver: "1.7.8-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs-extra:i386", ver: "1.7.8-0ubuntu0.14.10.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.7.8-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.7.8-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs:i386", ver: "1.7.8-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs:amd64", ver: "1.7.8-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs-extra:amd64", ver: "1.7.8-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "oxideqt-codecs-extra:i386", ver: "1.7.8-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

