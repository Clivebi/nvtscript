if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844370" );
	script_version( "2020-03-20T06:19:59+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-20 06:19:59 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-19 04:00:23 +0000 (Thu, 19 Mar 2020)" );
	script_name( "Ubuntu: Security Advisory for apache2 (USN-4307-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "USN", value: "4307-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-March/005365.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the USN-4307-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "As a security improvement, this update adds TLSv1.3 support to the Apache
HTTP Server package in Ubuntu 18.04 LTS.

TLSv1.3 is enabled by default, and in certain environments may cause
compatibility issues. The SSLProtocol directive may be used to disable
TLSv1.3 in these problematic environments." );
	script_tag( name: "affected", value: "'apache2' package(s) on Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.29-1ubuntu4.13", rls: "UBUNTU18.04 LTS" ) )){
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

