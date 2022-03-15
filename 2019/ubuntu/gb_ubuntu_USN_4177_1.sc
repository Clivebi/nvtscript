if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844276" );
	script_version( "2019-12-13T12:11:15+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-13 12:11:15 +0000 (Fri, 13 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-12-12 03:01:20 +0000 (Thu, 12 Dec 2019)" );
	script_name( "Ubuntu Update for rygel USN-4177-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.10" );
	script_xref( name: "USN", value: "4177-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005186.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rygel'
  package(s) announced via the USN-4177-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Rygel package automatically started the daemon
by default in user sessions. In certain environments, this resulted in
media being shared contrary to expectations." );
	script_tag( name: "affected", value: "'rygel' package(s) on Ubuntu 19.10." );
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
	if(!isnull( res = isdpkgvuln( pkg: "rygel", ver: "0.38.1-2ubuntu3.3", rls: "UBUNTU19.10" ) )){
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

