if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844124" );
	script_version( "2019-08-08T09:10:13+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-08-08 09:10:13 +0000 (Thu, 08 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-06 02:00:34 +0000 (Tue, 06 Aug 2019)" );
	script_name( "Ubuntu Update for glib2.0 USN-4049-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4049-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-4049-3/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glib2.0'
  package(s) announced via the USN-4049-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4049-1 fixed a vulnerability in GLib. The update introduced a regression
in Ubuntu 16.04 LTS causing a possibly memory leak. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that GLib created directories and files without properly
restricting permissions. An attacker could possibly use this issue to access
sensitive information." );
	script_tag( name: "affected", value: "'glib2.0' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-0", ver: "2.48.2-0ubuntu4.4", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libglib2.0-bin", ver: "2.48.2-0ubuntu4.4", rls: "UBUNTU16.04 LTS" ) )){
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

