if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843866" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2018-1000858" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-13 16:43:00 +0000 (Wed, 13 Feb 2019)" );
	script_tag( name: "creation_date", value: "2019-01-11 04:00:23 +0100 (Fri, 11 Jan 2019)" );
	script_name( "Ubuntu Update for gnupg2 USN-3853-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS|18\\.10)" );
	script_xref( name: "USN", value: "3853-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3853-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnupg2'
  package(s) announced via the USN-3853-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ben Fuhrmannek discovered that GnuPG incorrectly handled Web Key Directory
lookups. A remote attacker could possibly use this issue to cause a denial
of service, or perform Cross-Site Request Forgery attacks." );
	script_tag( name: "affected", value: "gnupg2 on Ubuntu 18.10,
  Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gnupg", ver: "2.2.4-1ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gpg-wks-client", ver: "2.2.4-1ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "gnupg", ver: "2.2.8-3ubuntu1.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gpg-wks-client", ver: "2.2.8-3ubuntu1.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

