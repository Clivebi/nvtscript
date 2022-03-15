if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842142" );
	script_version( "2019-11-27T15:23:21+0000" );
	script_tag( name: "last_modification", value: "2019-11-27 15:23:21 +0000 (Wed, 27 Nov 2019)" );
	script_tag( name: "creation_date", value: "2015-03-25 06:32:27 +0100 (Wed, 25 Mar 2015)" );
	script_cve_id( "CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320", "CVE-2011-0992", "CVE-2012-3543" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for mono USN-2547-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mono'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Mono TLS
implementation was vulnerable to the SKIP-TLS vulnerability. A remote
attacker could possibly use this issue to perform client impersonation attacks.
(CVE-2015-2318)

It was discovered that the Mono TLS implementation was vulnerable to the
FREAK vulnerability. A remote attacker or a man in the middle could
possibly use this issue to force the use of insecure ciphersuites.
(CVE-2015-2319)

It was discovered that the Mono TLS implementation still supported a
fallback to SSLv2. This update removes the functionality as use of SSLv2 is
known to be insecure. (CVE-2015-2320)

It was discovered that Mono incorrectly handled memory in certain
circumstances. A remote attacker could possibly use this issue to cause
Mono to crash, resulting in a denial of service, or to obtain sensitive
information. This issue only applied to Ubuntu 12.04 LTS. (CVE-2011-0992)

It was discovered that Mono incorrectly handled hash collisions. A remote
attacker could possibly use this issue to cause Mono to crash, resulting in
a denial of service. This issue only applied to Ubuntu 12.04 LTS.
(CVE-2012-3543)" );
	script_tag( name: "affected", value: "mono on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2547-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2547-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libmono-2.0-1", ver: "3.2.8+dfsg-4ubuntu2.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mono-runtime", ver: "3.2.8+dfsg-4ubuntu2.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libmono-2.0-1", ver: "3.2.8+dfsg-4ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mono-runtime", ver: "3.2.8+dfsg-4ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libmono-2.0-1", ver: "2.10.8.1-1ubuntu2.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "mono-runtime", ver: "2.10.8.1-1ubuntu2.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

