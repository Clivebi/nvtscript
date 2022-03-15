if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844577" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2016-9112", "CVE-2018-20847", "CVE-2018-21010", "CVE-2020-6851", "CVE-2020-8112", "CVE-2020-15389", "CVE-2019-12973" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 19:57:00 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-16 03:00:30 +0000 (Wed, 16 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for openjpeg2 (USN-4497-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4497-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005606.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the USN-4497-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenJPEG incorrectly handled certain image files. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2016-9112)

It was discovered that OpenJPEG did not properly handle certain input. If
OpenJPEG were supplied with specially crafted input, it could be made to crash
or potentially execute arbitrary code.
(CVE-2018-20847, CVE-2018-21010, CVE-2020-6851, CVE-2020-8112, CVE-2020-15389)

It was discovered that OpenJPEG incorrectly handled certain BMP files. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2019-12973)" );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-tools", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d-tools", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d7", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-dec-server", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-server", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-viewer", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libopenjpip7", ver: "2.1.2-1.1+deb9u5build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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

