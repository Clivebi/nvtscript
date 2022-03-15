if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842671" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-02 06:17:56 +0100 (Wed, 02 Mar 2016)" );
	script_cve_id( "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openssl USN-2914-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Yuval Yarom, Daniel Genkin, and Nadia Heninger
  discovered that OpenSSL was vulnerable to a side-channel attack on modular
  exponentiation. On certain CPUs, a local attacker could possibly use this
  issue to recover RSA keys. This flaw is known as CacheBleed. (CVE-2016-0702)

  Adam Langley discovered that OpenSSL incorrectly handled memory when
  parsing DSA private keys. A remote attacker could use this issue to cause
  OpenSSL to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-0705)

  Guido Vranken discovered that OpenSSL incorrectly handled hex digit
  calculation in the BN_hex2bn function. A remote attacker could use this
  issue to cause OpenSSL to crash, resulting in a denial of service, or
  possibly execute arbitrary code. (CVE-2016-0797)

  Emilia K&#228 sper discovered that OpenSSL incorrectly handled memory when
  performing SRP user database lookups. A remote attacker could possibly use
  this issue to cause OpenSSL to consume memory, resulting in a denial of
  service. (CVE-2016-0798)

  Guido Vranken discovered that OpenSSL incorrectly handled memory when
  printing very long strings. A remote attacker could use this issue to cause
  OpenSSL to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-0799)" );
	script_tag( name: "affected", value: "openssl on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2914-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2914-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu2.18", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1f-1ubuntu2.18", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1-4ubuntu5.35", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1-4ubuntu5.35", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.2d-0ubuntu1.4", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.2d-0ubuntu1.4", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

