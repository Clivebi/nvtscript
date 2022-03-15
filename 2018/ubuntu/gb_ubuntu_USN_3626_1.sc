if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843749" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2018-6914", "CVE-2018-8778", "CVE-2018-8780", "CVE-2018-8779" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-21 12:15:00 +0000 (Sun, 21 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:14:49 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for ruby2.3 USN-3626-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3626-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3626-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby2.3'
  package(s) announced via the USN-3626-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ruby incorrectly handled certain inputs. An
attacker could possibly use this to execute arbitrary code.
(CVE-2018-6914)

It was discovered that Ruby incorrectly handled certain inputs. An
attacker could possibly use this to access sensitive information.
(CVE-2018-8778, CVE-2018-8780)

It was discovered that Ruby incorrectly handled certain inputs. An
attacker could possibly use this to connect to an unintended socket.
(CVE-2018-8779)" );
	script_tag( name: "affected", value: "ruby2.3 on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.3.484-2ubuntu1.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libruby2.0", ver: "2.0.0.484-1ubuntu2.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.9.1", ver: "1.9.3.484-2ubuntu1.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.9.3", ver: "1.9.3.484-2ubuntu1.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby2.0", ver: "2.0.0.484-1ubuntu2.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libruby2.3", ver: "2.3.3-1ubuntu1.5", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby2.3", ver: "2.3.3-1ubuntu1.5", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libruby2.3", ver: "2.3.1-2~16.04.9", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby2.3", ver: "2.3.1-2~16.04.9", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

