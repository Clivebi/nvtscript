if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844899" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-20297" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 17:20:00 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-15 03:00:30 +0000 (Thu, 15 Apr 2021)" );
	script_name( "Ubuntu: Security Advisory for network-manager (USN-4914-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.10" );
	script_xref( name: "Advisory-ID", value: "USN-4914-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-April/005973.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'network-manager'
  package(s) announced via the USN-4914-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that NetworkManager incorrectly handled certain profiles.
A local attacker could possibly use this issue to cause NetworkManager to
crash, resulting in a denial of service." );
	script_tag( name: "affected", value: "'network-manager' package(s) on Ubuntu 20.10." );
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "network-manager", ver: "1.26.2-1ubuntu1.1", rls: "UBUNTU20.10" ) )){
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

