if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844386" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-11501" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 15:10:00 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-04-08 03:00:25 +0000 (Wed, 08 Apr 2020)" );
	script_name( "Ubuntu: Security Advisory for gnutls28 (USN-4322-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.10" );
	script_xref( name: "USN", value: "4322-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-April/005384.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls28'
  package(s) announced via the USN-4322-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GnuTLS incorrectly handled randomness when
performing DTLS negotiation. A remote attacker could possibly use this
issue to obtain sensitive information, contrary to expectations." );
	script_tag( name: "affected", value: "'gnutls28' package(s) on Ubuntu 19.10." );
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libgnutls30", ver: "3.6.9-5ubuntu1.1", rls: "UBUNTU19.10" ) )){
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

