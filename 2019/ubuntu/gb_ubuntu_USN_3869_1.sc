if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843882" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-11803" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-25 04:02:22 +0100 (Fri, 25 Jan 2019)" );
	script_name( "Ubuntu Update for subversion USN-3869-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.10" );
	script_xref( name: "USN", value: "3869-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3869-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'subversion' package(s) announced via the USN-3869-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "Ivan Zhakov discovered that Subversion
  incorrectly handled certain inputs. An attacker could possibly use this issue
  to cause a denial of service." );
	script_tag( name: "affected", value: "subversion on Ubuntu 18.10." );
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
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "libapache2-mod-svn", ver: "1.10.0-2ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.10.0-2ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "subversion", ver: "1.10.0-2ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

