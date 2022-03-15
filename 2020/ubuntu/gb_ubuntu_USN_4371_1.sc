if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844444" );
	script_version( "2021-07-09T11:00:55+0000" );
	script_cve_id( "CVE-2020-10703", "CVE-2020-12430" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 11:00:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-16 03:15:00 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-22 03:00:26 +0000 (Fri, 22 May 2020)" );
	script_name( "Ubuntu: Security Advisory for libvirt (USN-4371-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS)" );
	script_xref( name: "USN", value: "4371-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-May/005446.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the USN-4371-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libvirt incorrectly handled an active pool without a
target path. A remote attacker could possibly use this issue to cause
libvirt to crash, resulting in a denial of service. (CVE-2020-10703)

It was discovered that libvirt incorrectly handled memory when retrieving
certain domain statistics. A remote attacker could possibly use this issue
to cause libvirt to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 19.10. (CVE-2020-12430)" );
	script_tag( name: "affected", value: "'libvirt' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libvirt-clients", ver: "5.4.0-0ubuntu5.4", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "5.4.0-0ubuntu5.4", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "5.4.0-0ubuntu5.4", rls: "UBUNTU19.10" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libvirt-clients", ver: "4.0.0-1ubuntu8.17", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "4.0.0-1ubuntu8.17", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "4.0.0-1ubuntu8.17", rls: "UBUNTU18.04 LTS" ) )){
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

