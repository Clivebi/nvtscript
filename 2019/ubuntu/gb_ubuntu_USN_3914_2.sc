if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843980" );
	script_version( "2019-04-19T05:29:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-04-19 05:29:08 +0000 (Fri, 19 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-18 02:00:52 +0000 (Thu, 18 Apr 2019)" );
	script_name( "Ubuntu Update for ntfs-3g USN-3914-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3914-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3914-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'ntfs-3g' package(s) announced via the USN-3914-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "USN-3914-1 fixed vulnerabilities in NTFS-3G.
As an additional hardening measure, this update removes the setuid bit from the
ntfs-3g binary.

Original advisory details:

A heap buffer overflow was discovered in NTFS-3G when executing it with a
relative mount point path that is too long. A local attacker could
potentially exploit this to execute arbitrary code as the administrator." );
	script_tag( name: "affected", value: "'ntfs-3g' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2017.3.23-2ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2017.3.23-2ubuntu0.18.10.2", rls: "UBUNTU18.10" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2015.3.14AR.1-1ubuntu0.3", rls: "UBUNTU16.04 LTS" ) )){
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

