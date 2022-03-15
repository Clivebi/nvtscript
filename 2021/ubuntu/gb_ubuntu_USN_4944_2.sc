if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845014" );
	script_version( "2021-08-03T06:52:21+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-03 06:52:21 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-29 03:00:32 +0000 (Thu, 29 Jul 2021)" );
	script_name( "Ubuntu: Security Advisory for mariadb-10.3 (USN-4944-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4944-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006122.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb-10.3'
  package(s) announced via the USN-4944-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4944-1 fixed vulnerabilities in MariaDB. It caused a regression.
This update fixes the problem.

Original advisory details:

Ubuntu 20.04 has been updated to MariaDB 10.3.30." );
	script_tag( name: "affected", value: "'mariadb-10.3' package(s) on Ubuntu 20.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "mariadb-server", ver: "1:10.3.30-0ubuntu0.20.04.1", rls: "UBUNTU20.04 LTS" ) )){
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

