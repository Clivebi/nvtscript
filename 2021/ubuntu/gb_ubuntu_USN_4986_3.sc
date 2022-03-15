if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844975" );
	script_version( "2021-06-17T06:11:17+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-17 06:11:17 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-11 03:00:35 +0000 (Fri, 11 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for rpcbind (USN-4986-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4986-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006069.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpcbind'
  package(s) announced via the USN-4986-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4986-1 fixed a vulnerability in rpcbind. The update caused a regression
resulting in rpcbind crashing in certain environments. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that rpcbind incorrectly handled certain large data
sizes. A remote attacker could use this issue to cause rpcbind to consume
resources, leading to a denial of service." );
	script_tag( name: "affected", value: "'rpcbind' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "rpcbind", ver: "0.2.3-0.6ubuntu0.18.04.3", rls: "UBUNTU18.04 LTS" ) )){
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

