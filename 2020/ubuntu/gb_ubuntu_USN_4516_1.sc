if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844588" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2019-14855" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-22 06:15:00 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-18 03:00:22 +0000 (Fri, 18 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for gnupg2 (USN-4516-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4516-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005626.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnupg2'
  package(s) announced via the USN-4516-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that GnuPG signatures could be forged when the SHA-1
algorithm is being used. This update removes validating signatures based on
SHA-1 that were generated after 2019-01-19. In environments where this is
still required, a new option --allow-weak-key-signatures can be used to
revert this behaviour." );
	script_tag( name: "affected", value: "'gnupg2' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "gnupg", ver: "2.2.4-1ubuntu1.3", rls: "UBUNTU18.04 LTS" ) )){
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

