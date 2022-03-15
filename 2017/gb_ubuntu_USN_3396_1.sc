if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843292" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-19 07:35:30 +0200 (Sat, 19 Aug 2017)" );
	script_cve_id( "CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10243" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openjdk-7 USN-3396-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-7'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the JPEGImageReader
class in OpenJDK would incorrectly read unused image data. An attacker could use
this to specially construct a jpeg image file that when opened by a Java
application would cause a denial of service. (CVE-2017-10053)

It was discovered that the JAR verifier in OpenJDK did not properly handle
archives containing files missing digests. An attacker could use this to
modify the signed contents of a JAR file. (CVE-2017-10067)

It was discovered that integer overflows existed in the Hotspot component
of OpenJDK when generating range check loop predicates. An attacker could
use this to specially construct an untrusted Java application or applet
that could escape sandbox restrictions and cause a denial of service or
possibly execute arbitrary code. (CVE-2017-10074)

It was discovered that OpenJDK did not properly process parentheses in
function signatures. An attacker could use this to specially construct an
untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2017-10081)

It was discovered that the ThreadPoolExecutor class in OpenJDK did not
properly perform access control checks when cleaning up threads. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions and possibly
execute arbitrary code. (CVE-2017-10087)

It was discovered that the ServiceRegistry implementation in OpenJDK did
not perform access control checks in certain situations. An attacker could
use this to specially construct an untrusted Java application or applet
that escaped sandbox restrictions. (CVE-2017-10089)

It was discovered that the channel groups implementation in OpenJDK did not
properly perform access control checks in some situations. An attacker
could use this to specially construct an untrusted Java application or
applet that could escape sandbox restrictions. (CVE-2017-10090)

It was discovered that the DTM exception handling code in the JAXP
component of OpenJDK did not properly perform access control checks. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions.
(CVE-2017-10096)

It was discovered that the JAXP component of OpenJDK incorrectly granted
access to some internal resolvers. An attacker could use this to specially
construct an untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2017-10101)

It was discovered that the Distributed Garbage Collector (DGC) in OpenJDK
did not properly track references in some situations. A remote attacker
could possibly use t ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "openjdk-7 on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3396-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3396-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:amd64", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:i386", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u151-2.6.11-0ubuntu1.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

