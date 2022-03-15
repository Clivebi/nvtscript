if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844911" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2017-15107", "CVE-2019-14513" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2021-04-23 03:00:33 +0000 (Fri, 23 Apr 2021)" );
	script_name( "Ubuntu: Security Advisory for dnsmasq (USN-4924-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4924-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-April/005986.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the USN-4924-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Dnsmasq incorrectly handled certain wildcard
synthesized NSEC records. A remote attacker could possibly use this issue
to prove the non-existence of hostnames that actually exist.
(CVE-2017-15107)

It was discovered that Dnsmasq incorrectly handled certain large DNS
packets. A remote attacker could possibly use this issue to cause Dnsmasq
to crash, resulting in a denial of service. (CVE-2019-14513)" );
	script_tag( name: "affected", value: "'dnsmasq' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.75-1ubuntu0.16.04.10", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.75-1ubuntu0.16.04.10", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.75-1ubuntu0.16.04.10", rls: "UBUNTU16.04 LTS" ) )){
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

