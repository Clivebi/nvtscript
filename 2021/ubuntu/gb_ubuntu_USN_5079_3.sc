if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845067" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_cve_id( "CVE-2021-22945", "CVE-2021-22946", "CVE-2021-22947" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-22 01:00:38 +0000 (Wed, 22 Sep 2021)" );
	script_name( "Ubuntu: Security Advisory for curl (USN-5079-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-5079-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-September/006197.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the USN-5079-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-5079-1 fixed vulnerabilities in curl. One of the fixes introduced a
regression on Ubuntu 18.04 LTS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that curl incorrect handled memory when sending data to
an MQTT server. A remote attacker could use this issue to cause curl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2021-22945)
Patrick Monnerat discovered that curl incorrectly handled upgrades to TLS.
When receiving certain responses from servers, curl would continue without
TLS even when the option to require a successful upgrade to TLS was
specified. (CVE-2021-22946)
Patrick Monnerat discovered that curl incorrectly handled responses
received before STARTTLS. A remote attacker could possibly use this issue
to inject responses and intercept communications. (CVE-2021-22947)" );
	script_tag( name: "affected", value: "'curl' package(s) on Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.58.0-2ubuntu3.16", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.58.0-2ubuntu3.16", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.58.0-2ubuntu3.16", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.58.0-2ubuntu3.16", rls: "UBUNTU18.04 LTS" ) )){
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

