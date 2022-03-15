if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844558" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-11095", "CVE-2020-11096", "CVE-2020-11097", "CVE-2020-11098", "CVE-2020-11099", "CVE-2020-15103", "CVE-2020-4030", "CVE-2020-4031", "CVE-2020-4032", "CVE-2020-4033" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 10:15:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:52:22 +0530 (Wed, 02 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for freerdp2 (USN-4481-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4481-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005587.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp2'
  package(s) announced via the USN-4481-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that FreeRDP incorrectly handled certain memory
operations. A remote attacker could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code." );
	script_tag( name: "affected", value: "'freerdp2' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-client2-2", ver: "2.2.0+dfsg1-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-server2-2", ver: "2.2.0+dfsg1-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp2-2", ver: "2.2.0+dfsg1-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-client2-2", ver: "2.2.0+dfsg1-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-server2-2", ver: "2.2.0+dfsg1-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp2-2", ver: "2.2.0+dfsg1-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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
