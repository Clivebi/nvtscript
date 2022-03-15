if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844330" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2017-18187", "CVE-2018-0487", "CVE-2018-0488", "CVE-2018-0497", "CVE-2018-0498" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-10 16:15:00 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-06 04:00:18 +0000 (Thu, 06 Feb 2020)" );
	script_name( "Ubuntu: Security Advisory for mbedtls (USN-4267-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4267-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-February/005317.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mbedtls'
  package(s) announced via the USN-4267-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that mbedtls has a bounds-check bypass through an integer
overflow that can be used by an attacked to execute arbitrary code or cause a
denial of service.
(CVE-2017-18187)

It was discovered that mbedtls has a vulnerability where an attacker could
execute arbitrary code or cause a denial of service (buffer overflow)
via a crafted certificate chain that is mishandled during RSASSA-PSS
signature verification within a TLS or DTLS session.
(CVE-2018-0487)

It was discovered that mbedtls has a vulnerability where an attacker could
execute arbitrary code or cause a denial of service (heap corruption) via a
crafted application packet within a TLS or DTLS session.
(CVE-2018-0488)

It was discovered that mbedtls has a vulnerability that allows remote
attackers to achieve partial plaintext recovery (for a CBC based ciphersuite)
via a timing-based side-channel attack.
(CVE-2018-0497)

It was discovered that mbedtls has a vulnerability that allows local users to
achieve partial plaintext recovery (for a CBC based ciphersuite) via a
cache-based side-channel attack.
(CVE-2018-0498)" );
	script_tag( name: "affected", value: "'mbedtls' package(s) on Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libmbedcrypto0", ver: "2.2.1-2ubuntu0.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmbedtls10", ver: "2.2.1-2ubuntu0.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmbedx509-0", ver: "2.2.1-2ubuntu0.3", rls: "UBUNTU16.04 LTS" ) )){
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
}
exit( 0 );

