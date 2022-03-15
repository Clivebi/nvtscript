if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844753" );
	script_version( "2020-12-16T06:26:32+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-16 06:26:32 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-10 04:00:32 +0000 (Thu, 10 Dec 2020)" );
	script_name( "Ubuntu: Security Advisory for python-apt (USN-4668-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.10" );
	script_xref( name: "USN", value: "4668-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-December/005804.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-apt'
  package(s) announced via the USN-4668-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4668-1 fixed vulnerabilities in python-apt. That update caused a
regression by removing information describing the Ubuntu 20.10 release from
the Ubuntu templates.  This update fixes the problem by restoring this
information.

We apologize for the inconvenience.

Original advisory details:

Kevin Backhouse discovered that python-apt incorrectly handled
resources. A
local attacker could possibly use this issue to cause python-apt to
consume
resources, leading to a denial of service." );
	script_tag( name: "affected", value: "'python-apt' package(s) on Ubuntu 20.10." );
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
	if(!isnull( res = isdpkgvuln( pkg: "python3-apt", ver: "2.1.3ubuntu1.2", rls: "UBUNTU20.10" ) )){
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

